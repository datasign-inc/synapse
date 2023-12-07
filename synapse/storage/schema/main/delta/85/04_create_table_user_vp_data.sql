/* Copyright 2023 The Matrix.org Foundation C.I.C
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

CREATE TABLE IF NOT EXISTS user_vp_data (
    user_id TEXT NOT NULL,
    vp_type TEXT NOT NULL,
    num BIGINT NOT NULL,
    verified_main_claims TEXT NOT NULL,
    verified_all_claims TEXT NOT NULL,
    raw_vp_token TEXT NOT NULL,
    created_ts BIGINT NOT NULL,
    PRIMARY KEY (user_id, vp_type, num)
);
CREATE INDEX IF NOT EXISTS user_vp_data_user_id_vp_type_idx ON user_vp_data(user_id, vp_type);