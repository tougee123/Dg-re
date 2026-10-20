"""Pinned constructor/consumer slices, stopping before external effects."""
import json
import sys
from pathlib import Path

from bind_provenance import Sample, build as bind_build

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / 'dg239-protocol-receive-binding-20261019/evidence'))
from receive_slices import BytesState, CallBarrier, run

PINS = {
    0x10083CC48: '2a1c00d04a7d44f96afa04f9',
    0x100842618: '60fa44f9a3760a94607e03f9d0210014',
    0x100838470: '4a1c00b04a1944f96aea06f9',
    0x100841FEC: '61ea46f9607e43f97551019460ae08f9f9caff17',
    0x1008965B0: 'fd7bbfa9e81700d0085d41f900013fd6fd7bc1a8c0035fd6fd7bbfa9f9ffff97fd7bc1a8c0035fd6',
    0x10083E5C8: '68b248f9000140f9604204f9f7860a94604244f9081c00f0014142f9a81a00d0085d41f900013fd6604604f9a7e0ff17',
    0x100846134: '68b248f9000140f9c81b00f001a942f9681a00d0085d41f900013fd660d606f90fbbff17',
    0x10083652C: 'aa6d00d04af141f96aee07f96a1c00904a1544f96af207f9',
    0x1008555F0: '60f247f9ad2a0a9460ae05f9bffbff17',
    0x1008544F8: '68ee47f960ae45f969b248f96a1b00b0413943f9220140f9830080d200013fd660aa05f95b83ff17',
}
SELECTORS = {0x100BC1830: 'init', 0x100BC1480: 'bytes',
             0x100BC1550: 'length', 0x100BC1670: 'initWithData:encoding:'}


def build(sample):
    windows = []
    for address, pin in PINS.items():
        if sample.read(address, len(bytes.fromhex(pin))).hex() != pin:
            raise ValueError(f'changed code at {address:#x}')
        windows.append(sample.window(address, len(bytes.fromhex(pin))))
    for address, selector in SELECTORS.items():
        if sample.selector(address) != selector:
            raise ValueError(f'changed selector at {address:#x}')
    if sample.stub_symbol(0x100AE00A8)['name'] != '_objc_alloc':
        raise ValueError('unexpected allocation import')
    if sample.stub_symbol(0x100AE01B0)['name'] != '_objc_retainAutorelease':
        raise ValueError('unexpected ownership import')
    return {'sample_sha256': sample.sha256, 'windows': windows,
            'binding_evidence': bind_build(sample),
            'selectors': {hex(k): v for k, v in SELECTORS.items()},
            'allocation_import': sample.stub_symbol(0x100AE00A8),
            'retain_autorelease_import': sample.stub_symbol(0x100AE01B0),
            'same_transaction_decoder_proven': False,
            'external_effects_proven': False,
            'open': ['Allocation-to-init CFF reachability and real return object',
                     'Returning wrapper effects on frame and response cell',
                     'Actual receive append, parser and endpoint in one transaction',
                     'Writes/clears via objc_storeStrong and other aliases',
                     'Live NSString constructor target at global 0x1015EC3E0',
                     'Final response decoding and validation outcome']}


if __name__ == '__main__':
    print(json.dumps(build(Sample()), indent=2))
