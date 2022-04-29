# -*- coding: utf-8 -*-

import pytest

from fido_mds import FidoMetadataStore

__author__ = 'lundberg'


@pytest.fixture(scope='session')
def mds():
    return FidoMetadataStore()
