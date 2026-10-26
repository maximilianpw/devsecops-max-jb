#!/usr/bin/env python3
"""Valide un index contenant exactement les deux manifestes vérifiés."""

import json
import sys


def check(index, expected):
    manifests = index.get('manifests', [])
    actual = {}
    for manifest in manifests:
        platform = manifest.get('platform', {})
        key = platform.get('os', '') + '/' + platform.get('architecture', '')
        if key in actual:
            raise ValueError('plateforme dupliquée')
        actual[key] = manifest['digest']
    if len(manifests) != 2 or actual != expected:
        raise ValueError('index incomplet, plateforme ou digest inattendu')


if __name__ == '__main__':
    check(json.load(open(sys.argv[1])), {
        'linux/amd64': sys.argv[2], 'linux/arm64': sys.argv[3],
    })
