# Copyright 2014-2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
from typing import TYPE_CHECKING, List, Optional, Tuple

from synapse.api.constants import VPSessionStatus, VPType
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.roommember import ProfileInfo
from synapse.storage.engines import PostgresEngine
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

from synapse.api.errors import StoreError


class ProfileWorkerStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)
        self.server_name: str = hs.hostname
        self.database_engine = database.engine
        self.db_pool.updates.register_background_index_update(
            "profiles_full_user_id_key_idx",
            index_name="profiles_full_user_id_key",
            table="profiles",
            columns=["full_user_id"],
            unique=True,
        )

        self.db_pool.updates.register_background_update_handler(
            "populate_full_user_id_profiles", self.populate_full_user_id_profiles
        )
        self._clock = hs.get_clock()

    async def populate_full_user_id_profiles(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """
        Background update to populate the column `full_user_id` of the table
        profiles from entries in the column `user_local_part` of the same table
        """

        lower_bound_id = progress.get("lower_bound_id", "")

        def _get_last_id(txn: LoggingTransaction) -> Optional[str]:
            sql = """
                    SELECT user_id FROM profiles
                    WHERE user_id > ?
                    ORDER BY user_id
                    LIMIT 1 OFFSET 1000
                  """
            txn.execute(sql, (lower_bound_id,))
            res = txn.fetchone()
            if res:
                upper_bound_id = res[0]
                return upper_bound_id
            else:
                return None

        def _process_batch(
            txn: LoggingTransaction, lower_bound_id: str, upper_bound_id: str
        ) -> None:
            sql = """
                    UPDATE profiles
                    SET full_user_id = '@' || user_id || ?
                    WHERE ? < user_id AND user_id <= ? AND full_user_id IS NULL
                   """
            txn.execute(sql, (f":{self.server_name}", lower_bound_id, upper_bound_id))

        def _final_batch(txn: LoggingTransaction, lower_bound_id: str) -> None:
            sql = """
                    UPDATE profiles
                    SET full_user_id = '@' || user_id || ?
                    WHERE ? < user_id AND full_user_id IS NULL
                   """
            txn.execute(
                sql,
                (
                    f":{self.server_name}",
                    lower_bound_id,
                ),
            )

            if isinstance(self.database_engine, PostgresEngine):
                sql = """
                        ALTER TABLE profiles VALIDATE CONSTRAINT full_user_id_not_null
                      """
                txn.execute(sql)

        upper_bound_id = await self.db_pool.runInteraction(
            "populate_full_user_id_profiles", _get_last_id
        )

        if upper_bound_id is None:
            await self.db_pool.runInteraction(
                "populate_full_user_id_profiles", _final_batch, lower_bound_id
            )

            await self.db_pool.updates._end_background_update(
                "populate_full_user_id_profiles"
            )
            return 1

        await self.db_pool.runInteraction(
            "populate_full_user_id_profiles",
            _process_batch,
            lower_bound_id,
            upper_bound_id,
        )

        progress["lower_bound_id"] = upper_bound_id

        await self.db_pool.runInteraction(
            "populate_full_user_id_profiles",
            self.db_pool.updates._background_update_progress_txn,
            "populate_full_user_id_profiles",
            progress,
        )

        return 50

    async def get_profileinfo(self, user_id: UserID) -> ProfileInfo:
        profile = await self.db_pool.simple_select_one(
            table="profiles",
            keyvalues={"full_user_id": user_id.to_string()},
            retcols=("displayname", "avatar_url"),
            desc="get_profileinfo",
            allow_none=True,
        )
        if profile is None:
            # no match
            return ProfileInfo(None, None)

        return ProfileInfo(avatar_url=profile[1], display_name=profile[0])

    async def get_profile_displayname(self, user_id: UserID) -> Optional[str]:
        return await self.db_pool.simple_select_one_onecol(
            table="profiles",
            keyvalues={"full_user_id": user_id.to_string()},
            retcol="displayname",
            desc="get_profile_displayname",
        )

    async def get_profile_avatar_url(self, user_id: UserID) -> Optional[str]:
        return await self.db_pool.simple_select_one_onecol(
            table="profiles",
            keyvalues={"full_user_id": user_id.to_string()},
            retcol="avatar_url",
            desc="get_profile_avatar_url",
        )

    async def create_profile(self, user_id: UserID) -> None:
        user_localpart = user_id.localpart
        await self.db_pool.simple_insert(
            table="profiles",
            values={"user_id": user_localpart, "full_user_id": user_id.to_string()},
            desc="create_profile",
        )

    async def set_profile_displayname(
        self, user_id: UserID, new_displayname: Optional[str]
    ) -> None:
        """
        Set the display name of a user.

        Args:
            user_id: The user's ID.
            new_displayname: The new display name. If this is None, the user's display
                name is removed.
        """
        user_localpart = user_id.localpart
        await self.db_pool.simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={
                "displayname": new_displayname,
                "full_user_id": user_id.to_string(),
            },
            desc="set_profile_displayname",
        )

    async def set_profile_avatar_url(
        self, user_id: UserID, new_avatar_url: Optional[str]
    ) -> None:
        """
        Set the avatar of a user.

        Args:
            user_id: The user's ID.
            new_avatar_url: The new avatar URL. If this is None, the user's avatar is
                removed.
        """
        user_localpart = user_id.localpart
        await self.db_pool.simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={"avatar_url": new_avatar_url, "full_user_id": user_id.to_string()},
            desc="set_profile_avatar_url",
        )

    async def register_vp_session(
        self, sid: str, vp_type: VPType, ro_nonce: str, user_id: str
    ) -> None:
        await self.db_pool.simple_insert(
            table="vp_session_management",
            values={
                "sid": sid,
                "vp_type": vp_type.value,
                "status": "created",
                "ro_nonce": ro_nonce,
                "user_id": user_id,
                "created_ts": self._clock.time_msec(),
            },
            desc="register_vp_session",
        )

    async def register_vp_data(
        self,
        user_id: str,
        vp_type: VPType,
        verifies_main_claims: dict,
        verified_all_claims: dict,
        raw_vp_token: str,
    ) -> None:
        sql = """INSERT INTO user_vp_data
        (user_id, vp_type,
        num,
        verified_main_claims,
        verified_all_claims, raw_vp_token, created_ts)
        VALUES
        (?, ?,
        (SELECT COALESCE(MAX(num), 0) + 1
         FROM user_vp_data WHERE user_id = ? AND vp_type = ?),
        ?, ?, ?, ?)
        """
        await self.db_pool.execute(
            "register_user_vp_data",
            sql,
            user_id,
            vp_type.value,
            user_id,
            vp_type.value,
            json.dumps(verifies_main_claims),
            json.dumps(verified_all_claims),
            raw_vp_token,
            self._clock.time_msec(),
        )

    async def delete_vp_data(self, user_id: str, vp_type: VPType, num: int) -> None:
        await self.db_pool.simple_delete(
            "user_vp_data",
            keyvalues={"user_id": user_id, "vp_type": vp_type.value, "num": num},
            desc="delete user_vp_data",
        )

    async def lookup_vp_data(
        self, user_id: str, vp_type: VPType
    ) -> List[Tuple[int, dict, str, str]]:
        ret = await self.db_pool.simple_select_list(
            "user_vp_data",
            keyvalues={"user_id": user_id, "vp_type": vp_type.value},
            retcols=[
                "num",
                "verified_main_claims",
                "verified_all_claims",
                "raw_vp_token",
            ],
            desc="lookup_vp_data",
        )
        return [(x[0], json.loads(x[1]), json.loads(x[2]), x[3]) for x in ret]

    async def lookup_vp_userid(
        self, sid: str
    ) -> Optional[str]:
        try:
            ret = await self.db_pool.simple_select_one(
                table="vp_session_management",
                keyvalues={"sid": sid},
                retcols=["user_id"],
            )
        except StoreError:
            return None
        (user_id,) = ret
        return user_id

    async def lookup_vp_ro_nonce(self, sid: str) -> Optional[str]:
        try:
            ret = await self.db_pool.simple_select_one(
                table="vp_session_management",
                keyvalues={"sid": sid},
                retcols=["ro_nonce"],
            )
        except StoreError:
            return None
        (ro_nonce,) = ret
        return ro_nonce

    async def update_vp_session_status(self, sid: str, status: VPSessionStatus) -> None:
        # todo: Use transaction
        await self.db_pool.simple_update_one(
            table="vp_session_management",
            keyvalues={"sid": sid},
            updatevalues={"status": status.value},
        )

    async def invalidate_vp_session(self, sid: str) -> None:
        await self.update_vp_session_status(sid, VPSessionStatus.INVALIDATED)

    async def lookup_vp_type(self, sid: str) -> Optional[VPType]:
        try:
            ret = await self.db_pool.simple_select_one(
                table="vp_session_management",
                keyvalues={"sid": sid},
                retcols=["vp_type"],
            )
        except StoreError:
            return None

        (vp_type,) = ret
        return VPType(vp_type)

    async def validate_vp_session(
        self, sid: str, expected_status: VPSessionStatus
    ) -> bool:
        # todo: Allow reference from other functions
        vp_session_timeout = 30000000

        if sid == "":
            return False

        try:
            ret = await self.db_pool.simple_select_one(
                table="vp_session_management",
                keyvalues={"sid": sid},
                retcols=["status", "created_ts"],
            )
        except StoreError:
            return False

        raw_st, created_ts = ret
        status = VPSessionStatus(raw_st)
        if status == VPSessionStatus.INVALIDATED:
            return False

        now = self._clock.time_msec()
        if created_ts + vp_session_timeout < now:
            return False

        return status == expected_status


class ProfileStore(ProfileWorkerStore):
    pass
