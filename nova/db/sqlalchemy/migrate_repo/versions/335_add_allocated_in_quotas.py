# Copyright 2015 OpenStack Foundation
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from sqlalchemy import Column, Integer, MetaData, Table


def upgrade(migrate_engine):
    meta = MetaData(bind=migrate_engine)

    quotas = Table('quotas', meta, autoload=True)
    shadow_quotas = Table('shadow_quotas', meta, autoload=True)

    child_hard_limits = Column('child_hard_limits', Integer, default=0)
    if not hasattr(quotas.c, 'child_hard_limits'):
        quotas.create_column(child_hard_limits)
    if not hasattr(shadow_quotas.c, 'child_hard_limits'):
        shadow_quotas.create_column(child_hard_limits.copy())
