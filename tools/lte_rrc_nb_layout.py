"""Generated unaligned-PER layout table for LTE RRC (TS 36.331).

Produced by tools/asn1gen.py -- DO NOT EDIT BY HAND.

Oracle:    pycrate 0.8.1
Generated: 2026-10-17 19:40:10

This file is plain data: it imports nothing and is consumed by
tools/lte_per.py, which implements the PER engine.

TYPES maps an ASN.1 type name to a layout node:
  ref      {t: <type name>}
  bool     {}                                  True/False, 1 bit
  null     {}                                  no bits
  int      {lb, ub, ext}                       constrained whole number
  enum     {names, ext}                        constrained index
  bits     {size, ext}                         size [N,N] == fixed
  octets   {size, ext, containing}             containing is a note only
  seq      {ext, comp, extadd}                 comp = [name, node, optional, default]
  choice   {ext, alts, extadd}                 alts = [name, node]
  seqof    {size, ext, of}
  unsupported {why}                            engine raises PerError
Extension additions are one OPEN TYPE each:
  {k: extgrp, names, node}   a group of additions, node is its seq
  {k: extone, name, node}    a lone addition, node is that component
"""

# Explicitly requested root types (--types), in the order given.
ROOTS = [
    'MasterInformationBlock_NB',
    'BCCH_BCH_Message_NB',
    'SystemInformationBlockType1_NB',
    'SystemInformation_NB',
    'SystemInformationBlockType2_NB_r13',
    'SystemInformationBlockType3_NB_r13',
    'SystemInformationBlockType4_NB_r13',
    'SystemInformationBlockType5_NB_r13',
    'SystemInformationBlockType14_NB_r13',
    'BCCH_DL_SCH_Message_NB',
]

# Reason strings for every construct the generator could not express.
# Keyed by the type that contains it; the engine raises PerError on them.
UNSUPPORTED = {
}

TYPES = {
    'AB_ConfigPLMN_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ab-Config-r13',
                {
                    'k': 'ref',
                    't': 'AB_Config_NB_r13',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'AB_Config_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ab-Category-r13',
                {
                    'k': 'enum',
                    'names': ['a', 'b', 'c'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'ab-BarringBitmap-r13',
                {
                    'k': 'bits',
                    'size': [10, 10],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'ab-BarringForExceptionData-r13',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ab-BarringForSpecialAC-r13',
                {
                    'k': 'bits',
                    'size': [5, 5],
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'ACK_NACK_NumRepetitions_NB_r13': {
        'k': 'enum',
        'names': ['r1', 'r2', 'r4', 'r8', 'r16', 'r32', 'r64', 'r128'],
        'ext': None,
    },
    'ARFCN_ValueEUTRA': {
        'k': 'int',
        'lb': 0,
        'ub': 65535,
        'ext': False,
    },
    'ARFCN_ValueEUTRA_r9': {
        'k': 'int',
        'lb': 0,
        'ub': 262143,
        'ext': False,
    },
    'ARFCN_ValueGERAN': {
        'k': 'int',
        'lb': 0,
        'ub': 1023,
        'ext': False,
    },
    'AdditionalBandInfoList_NB_r14': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'FreqBandIndicator_NB_r13',
        },
    },
    'AdditionalSpectrumEmission': {
        'k': 'int',
        'lb': 1,
        'ub': 32,
        'ext': False,
    },
    'BCCH_BCH_MessageType_NB': {
        'k': 'ref',
        't': 'MasterInformationBlock_NB',
    },
    'BCCH_BCH_Message_NB': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'message',
                {
                    'k': 'ref',
                    't': 'BCCH_BCH_MessageType_NB',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'BCCH_Config_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'modificationPeriodCoeff-r13',
                {
                    'k': 'enum',
                    'names': ['n16', 'n32', 'n64', 'n128'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'BCCH_DL_SCH_MessageType_NB': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'c1',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'systemInformation-r13',
                            {
                                'k': 'ref',
                                't': 'SystemInformation_NB',
                            },
                        ],
                        [
                            'systemInformationBlockType1-r13',
                            {
                                'k': 'ref',
                                't': 'SystemInformationBlockType1_NB',
                            },
                        ],
                    ],
                    'extadd': [],
                },
            ],
            [
                'messageClassExtension',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [],
                    'extadd': [],
                },
            ],
        ],
        'extadd': [],
    },
    'BCCH_DL_SCH_Message_NB': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'message',
                {
                    'k': 'ref',
                    't': 'BCCH_DL_SCH_MessageType_NB',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'BandIndicatorGERAN': {
        'k': 'enum',
        'names': ['dcs1800', 'pcs1900'],
        'ext': None,
    },
    'CBP_Config_NB_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nrsrpMin-r17',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                False,
                None,
            ],
            [
                'nB-r17',
                {
                    'k': 'enum',
                    'names': [
                        'fourT',
                        'twoT',
                        'oneT',
                        'halfT',
                        'quarterT',
                        'one8thT',
                        'one16thT',
                        'one32ndT',
                        'one64thT',
                        'one128thT',
                        'one256thT',
                        'one512thT',
                        'one1024thT',
                        'spare3',
                        'spare2',
                        'spare1',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ue-SpecificDRX-CycleMin-r17',
                {
                    'k': 'enum',
                    'names': ['rf32', 'rf64', 'rf128', 'rf256'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqEUTRA_NB_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'carrierFreq-r16',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueEUTRA_r9',
                },
                False,
                None,
            ],
            [
                'sib1-r16',
                {
                    'k': 'enum',
                    'names': ['supported'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'sib1-BR-r16',
                {
                    'k': 'enum',
                    'names': ['supported'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqListEUTRA_NB_r16': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CarrierFreqEUTRA_NB_r16',
        },
    },
    'CarrierFreqList_NB_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'carrierFreqList-r18',
                {
                    'k': 'seqof',
                    'size': [1, 8],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'CarrierFreq_NB_r13',
                    },
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqList_v1800': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'ARFCN_ValueEUTRA',
        },
    },
    'CarrierFreq_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'carrierFreq-r13',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueEUTRA_r9',
                },
                False,
                None,
            ],
            [
                'carrierFreqOffset-r13',
                {
                    'k': 'enum',
                    'names': [
                        'v-10',
                        'v-9',
                        'v-8',
                        'v-7',
                        'v-6',
                        'v-5',
                        'v-4',
                        'v-3',
                        'v-2',
                        'v-1',
                        'v-0dot5',
                        'v0',
                        'v1',
                        'v2',
                        'v3',
                        'v4',
                        'v5',
                        'v6',
                        'v7',
                        'v8',
                        'v9',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreq_NB_v1550': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'carrierFreqOffset-v1550',
                {
                    'k': 'enum',
                    'names': ['v-8dot5', 'v-4dot5', 'v3dot5', 'v7dot5'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqsGERAN': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'startingARFCN',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueGERAN',
                },
                False,
                None,
            ],
            [
                'bandIndicator',
                {
                    'k': 'ref',
                    't': 'BandIndicatorGERAN',
                },
                False,
                None,
            ],
            [
                'followingARFCNs',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'explicitListOfARFCNs',
                            {
                                'k': 'ref',
                                't': 'ExplicitListOfARFCNs',
                            },
                        ],
                        [
                            'equallySpacedARFCNs',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'arfcn-Spacing',
                                        {
                                            'k': 'int',
                                            'lb': 1,
                                            'ub': 8,
                                            'ext': False,
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'numberOfFollowingARFCNs',
                                        {
                                            'k': 'int',
                                            'lb': 0,
                                            'ub': 31,
                                            'ext': False,
                                        },
                                        False,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                        ],
                        [
                            'variableBitMapOfARFCNs',
                            {
                                'k': 'octets',
                                'size': [1, 16],
                                'ext': False,
                                'containing': None,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqsGERAN_NB_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'carrierFreqs-r16',
                {
                    'k': 'ref',
                    't': 'CarrierFreqsGERAN',
                },
                False,
                None,
            ],
            [
                'ec-GSM-IOT-r16',
                {
                    'k': 'enum',
                    'names': ['supported'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'peo-r16',
                {
                    'k': 'enum',
                    'names': ['supported'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqsListGERAN_NB_r16': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CarrierFreqsGERAN_NB_r16',
        },
    },
    'CellIdentity': {
        'k': 'bits',
        'size': [28, 28],
        'ext': False,
    },
    'CellReselectionInfoCommon_NB_v1450': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                's-SearchDeltaP-r14',
                {
                    'k': 'enum',
                    'names': ['dB6', 'dB9', 'dB12', 'dB15'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'CellSelectionInfo_NB_v1350': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'delta-RxLevMin-v1350',
                {
                    'k': 'int',
                    'lb': -8,
                    'ub': -1,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'CellSelectionInfo_NB_v1430': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'powerClass14dBm-Offset-r14',
                {
                    'k': 'enum',
                    'names': ['dB-6', 'dB-3', 'dB3', 'dB6', 'dB9', 'dB12'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ce-authorisationOffset-r14',
                {
                    'k': 'enum',
                    'names': ['dB5', 'dB10', 'dB15', 'dB20', 'dB25', 'dB30', 'dB35'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'ChannelRasterOffset_NB_r13': {
        'k': 'enum',
        'names': ['khz-7dot5', 'khz-2dot5', 'khz2dot5', 'khz7dot5'],
        'ext': None,
    },
    'ConnMeasConfig_NB_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                's-MeasureIntra-r17',
                {
                    'k': 'ref',
                    't': 'NRSRP_Range_NB_r14',
                },
                False,
                None,
            ],
            [
                's-MeasureInter-r17',
                {
                    'k': 'ref',
                    't': 'NRSRP_Range_NB_r14',
                },
                True,
                None,
            ],
            [
                'neighCellMeasCriteria-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            's-MeasureDeltaP-r17',
                            {
                                'k': 'enum',
                                'names': ['dB6', 'dB9', 'dB12', 'dB15'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            't-MeasureDeltaP-r17',
                            {
                                'k': 'enum',
                                'names': ['s15', 's30', 's45', 's60'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'CoverageBasedPagingConfig_NB_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'cbp-HystTimer-r17',
                {
                    'k': 'enum',
                    'names': [
                        'ms2560',
                        'ms7680',
                        'ms12800',
                        'ms17920',
                        'ms23040',
                        'ms28160',
                        'ms33280',
                        'ms40960',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'cbp-ConfigList-r17',
                {
                    'k': 'seqof',
                    'size': [1, 2],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'CBP_Config_NB_r17',
                    },
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'DL_Bitmap_NB_r13': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'subframePattern10-r13',
                {
                    'k': 'bits',
                    'size': [10, 10],
                    'ext': False,
                },
            ],
            [
                'subframePattern40-r13',
                {
                    'k': 'bits',
                    'size': [40, 40],
                    'ext': False,
                },
            ],
        ],
        'extadd': [],
    },
    'DL_CarrierConfigCommon_NB_r14': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'dl-CarrierFreq-r14',
                {
                    'k': 'ref',
                    't': 'CarrierFreq_NB_r13',
                },
                False,
                None,
            ],
            [
                'downlinkBitmapNonAnchor-r14',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'useNoBitmap-r14',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'useAnchorBitmap-r14',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'explicitBitmapConfiguration-r14',
                            {
                                'k': 'ref',
                                't': 'DL_Bitmap_NB_r13',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'dl-GapNonAnchor-r14',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'useNoGap-r14',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'useAnchorGapConfig-r14',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'explicitGapConfiguration-r14',
                            {
                                'k': 'ref',
                                't': 'DL_GapConfig_NB_r13',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'inbandCarrierInfo-r14',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'samePCI-Indicator-r14',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'samePCI-r14',
                                        {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    'indexToMidPRB-r14',
                                                    {
                                                        'k': 'int',
                                                        'lb': -55,
                                                        'ub': 54,
                                                        'ext': False,
                                                    },
                                                    False,
                                                    None,
                                                ],
                                            ],
                                            'extadd': [],
                                        },
                                    ],
                                    [
                                        'differentPCI-r14',
                                        {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    'eutra-NumCRS-Ports-r14',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['same', 'four'],
                                                        'ext': None,
                                                    },
                                                    False,
                                                    None,
                                                ],
                                            ],
                                            'extadd': [],
                                        },
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'eutraControlRegionSize-r14',
                            {
                                'k': 'enum',
                                'names': ['n1', 'n2', 'n3'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'nrs-PowerOffsetNonAnchor-r14',
                {
                    'k': 'enum',
                    'names': ['dB-12', 'dB-10', 'dB-8', 'dB-6', 'dB-4', 'dB-2', 'dB0', 'dB3'],
                    'ext': None,
                },
                False,
                'dB0',
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['dl-GapNonAnchor-v1530'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'dl-GapNonAnchor-v1530',
                            {
                                'k': 'ref',
                                't': 'DL_GapConfig_NB_v1530',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['dl-CarrierFreq-v1550'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'dl-CarrierFreq-v1550',
                            {
                                'k': 'ref',
                                't': 'CarrierFreq_NB_v1550',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'DL_ConfigCommonList_NB_r14': {
        'k': 'seqof',
        'size': [1, 15],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'DL_ConfigCommon_NB_r14',
        },
    },
    'DL_ConfigCommon_NB_r14': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'dl-CarrierConfig-r14',
                {
                    'k': 'ref',
                    't': 'DL_CarrierConfigCommon_NB_r14',
                },
                False,
                None,
            ],
            [
                'pcch-Config-r14',
                {
                    'k': 'ref',
                    't': 'PCCH_Config_NB_r14',
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['wus-Config-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'wus-Config-r15',
                            {
                                'k': 'ref',
                                't': 'WUS_ConfigPerCarrier_NB_r15',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['gwus-Config-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'gwus-Config-r16',
                            {
                                'k': 'ref',
                                't': 'WUS_ConfigPerCarrier_NB_r15',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['pcch-Config-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'pcch-Config-r17',
                            {
                                'k': 'ref',
                                't': 'PCCH_Config_NB_r17',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'DL_GapConfig_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'dl-GapThreshold-r13',
                {
                    'k': 'enum',
                    'names': ['n32', 'n64', 'n128', 'n256'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'dl-GapPeriodicity-r13',
                {
                    'k': 'enum',
                    'names': ['sf64', 'sf128', 'sf256', 'sf512'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'dl-GapDurationCoeff-r13',
                {
                    'k': 'enum',
                    'names': ['oneEighth', 'oneFourth', 'threeEighth', 'oneHalf'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'DL_GapConfig_NB_v1530': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'dl-GapPeriodicity-v1530',
                {
                    'k': 'enum',
                    'names': ['sf1024'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'EDT_TBS_InfoList_NB_r15': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EDT_TBS_NB_r15',
        },
    },
    'EDT_TBS_NB_r15': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'edt-SmallTBS-Enabled-r15',
                {
                    'k': 'bool',
                },
                False,
                None,
            ],
            [
                'edt-TBS-r15',
                {
                    'k': 'enum',
                    'names': ['b328', 'b408', 'b504', 'b584', 'b680', 'b808', 'b936', 'b1000'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'EphemerisOrbitalParameters_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'semiMajorAxis-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 8589934591,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'eccentricity-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1048575,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'periapsis-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 268435455,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'longitude-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 268435455,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'inclination-r17',
                {
                    'k': 'int',
                    'lb': -67108864,
                    'ub': 67108863,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'anomaly-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 268435455,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'EphemerisStateVectors_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'positionX-r17',
                {
                    'k': 'ref',
                    't': 'PositionStateVector_r17',
                },
                False,
                None,
            ],
            [
                'positionY-r17',
                {
                    'k': 'ref',
                    't': 'PositionStateVector_r17',
                },
                False,
                None,
            ],
            [
                'positionZ-r17',
                {
                    'k': 'ref',
                    't': 'PositionStateVector_r17',
                },
                False,
                None,
            ],
            [
                'velocityVX-r17',
                {
                    'k': 'ref',
                    't': 'VelocityStateVector_r17',
                },
                False,
                None,
            ],
            [
                'velocityVY-r17',
                {
                    'k': 'ref',
                    't': 'VelocityStateVector_r17',
                },
                False,
                None,
            ],
            [
                'velocityVZ-r17',
                {
                    'k': 'ref',
                    't': 'VelocityStateVector_r17',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'ExplicitListOfARFCNs': {
        'k': 'seqof',
        'size': [0, 31],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'ARFCN_ValueGERAN',
        },
    },
    'FreqBandIndicator_NB_r13': {
        'k': 'int',
        'lb': 1,
        'ub': 256,
        'ext': False,
    },
    'GWUS_Config_NB_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'groupAlternation-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'commonSequence-r16',
                {
                    'k': 'enum',
                    'names': ['g0', 'g126'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'timeParameters-r16',
                {
                    'k': 'ref',
                    't': 'WUS_Config_NB_r15',
                },
                True,
                None,
            ],
            [
                'resourceConfigDRX-r16',
                {
                    'k': 'ref',
                    't': 'GWUS_ResourceConfig_NB_r16',
                },
                False,
                None,
            ],
            [
                'resourceConfig-eDRX-Short-r16',
                {
                    'k': 'ref',
                    't': 'GWUS_ResourceConfig_NB_r16',
                },
                True,
                None,
            ],
            [
                'resourceConfig-eDRX-Long-r16',
                {
                    'k': 'ref',
                    't': 'GWUS_ResourceConfig_NB_r16',
                },
                True,
                None,
            ],
            [
                'probThreshList-r16',
                {
                    'k': 'ref',
                    't': 'GWUS_ProbThreshList_NB_r16',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'GWUS_GroupsForServiceList_NB_r16': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'int',
            'lb': 1,
            'ub': 15,
            'ext': False,
        },
    },
    'GWUS_NumGroupsList_NB_r16': {
        'k': 'seqof',
        'size': [1, 2],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'GWUS_NumGroups_NB_r16',
        },
    },
    'GWUS_NumGroups_NB_r16': {
        'k': 'enum',
        'names': ['n1', 'n2', 'n4', 'n8'],
        'ext': None,
    },
    'GWUS_Paging_ProbThresh_NB_r16': {
        'k': 'enum',
        'names': ['p20', 'p30', 'p40', 'p50', 'p60', 'p70', 'p80', 'p90'],
        'ext': None,
    },
    'GWUS_ProbThreshList_NB_r16': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'GWUS_Paging_ProbThresh_NB_r16',
        },
    },
    'GWUS_ResourceConfig_NB_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'resourcePosition-r16',
                {
                    'k': 'enum',
                    'names': ['primary', 'secondary'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'numGroupsList-r16',
                {
                    'k': 'ref',
                    't': 'GWUS_NumGroupsList_NB_r16',
                },
                True,
                None,
            ],
            [
                'groupsForServiceList-r16',
                {
                    'k': 'ref',
                    't': 'GWUS_GroupsForServiceList_NB_r16',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'Guardband_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'rasterOffset-r13',
                {
                    'k': 'ref',
                    't': 'ChannelRasterOffset_NB_r13',
                },
                False,
                None,
            ],
            [
                'spare',
                {
                    'k': 'bits',
                    'size': [3, 3],
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'Inband_DifferentPCI_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'eutra-NumCRS-Ports-r13',
                {
                    'k': 'enum',
                    'names': ['same', 'four'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'rasterOffset-r13',
                {
                    'k': 'ref',
                    't': 'ChannelRasterOffset_NB_r13',
                },
                False,
                None,
            ],
            [
                'spare',
                {
                    'k': 'bits',
                    'size': [2, 2],
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'Inband_SamePCI_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'eutra-CRS-SequenceInfo-r13',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 31,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqCarrierFreqInfo_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'dl-CarrierFreq-r13',
                {
                    'k': 'ref',
                    't': 'CarrierFreq_NB_r13',
                },
                False,
                None,
            ],
            [
                'q-RxLevMin-r13',
                {
                    'k': 'ref',
                    't': 'Q_RxLevMin',
                },
                False,
                None,
            ],
            [
                'q-QualMin-r13',
                {
                    'k': 'ref',
                    't': 'Q_QualMin_r9',
                },
                True,
                None,
            ],
            [
                'p-Max-r13',
                {
                    'k': 'ref',
                    't': 'P_Max',
                },
                True,
                None,
            ],
            [
                'q-OffsetFreq-r13',
                {
                    'k': 'ref',
                    't': 'Q_OffsetRange',
                },
                False,
                'dB0',
            ],
            [
                'interFreqNeighCellList-r13',
                {
                    'k': 'ref',
                    't': 'InterFreqNeighCellList_NB_r13',
                },
                True,
                None,
            ],
            [
                'interFreqExcludedCellList-r13',
                {
                    'k': 'ref',
                    't': 'InterFreqExcludedCellList_NB_r13',
                },
                True,
                None,
            ],
            [
                'multiBandInfoList-r13',
                {
                    'k': 'ref',
                    't': 'MultiBandInfoList_NB_r13',
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['delta-RxLevMin-v1350'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'delta-RxLevMin-v1350',
                            {
                                'k': 'int',
                                'lb': -8,
                                'ub': -1,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['powerClass14dBm-Offset-r14', 'ce-AuthorisationOffset-r14'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'powerClass14dBm-Offset-r14',
                            {
                                'k': 'enum',
                                'names': ['dB-6', 'dB-3', 'dB3', 'dB6', 'dB9', 'dB12'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'ce-AuthorisationOffset-r14',
                            {
                                'k': 'enum',
                                'names': ['dB5', 'dB10', 'dB15', 'dB20', 'dB25', 'dB30', 'dB35'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['nsss-RRM-Config-r15', 'interFreqNeighCellList-v1530'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nsss-RRM-Config-r15',
                            {
                                'k': 'ref',
                                't': 'NSSS_RRM_Config_NB_r15',
                            },
                            True,
                            None,
                        ],
                        [
                            'interFreqNeighCellList-v1530',
                            {
                                'k': 'ref',
                                't': 'InterFreqNeighCellList_NB_v1530',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['dl-CarrierFreq-v1550'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'dl-CarrierFreq-v1550',
                            {
                                'k': 'ref',
                                't': 'CarrierFreq_NB_v1550',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'InterFreqCarrierFreqInfo_NB_v1820': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'satelliteAssistanceInfo-r18',
                {
                    'k': 'seqof',
                    'size': [1, 4],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SatelliteId_r18',
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqCarrierFreqList_NB_r13': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo_NB_r13',
        },
    },
    'InterFreqCarrierFreqList_NB_v1820': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo_NB_v1820',
        },
    },
    'InterFreqExcludedCellList_NB_r13': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PhysCellId',
        },
    },
    'InterFreqNeighCellInfo_NB_v1530': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nsss-RRM-Config-r15',
                {
                    'k': 'ref',
                    't': 'NSSS_RRM_Config_NB_r15',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqNeighCellList_NB_r13': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PhysCellId',
        },
    },
    'InterFreqNeighCellList_NB_v1530': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqNeighCellInfo_NB_v1530',
        },
    },
    'IntraFreqCellReselectionInfo_NB_v1350': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'delta-RxLevMin-v1350',
                {
                    'k': 'int',
                    'lb': -8,
                    'ub': -1,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'IntraFreqCellReselectionInfo_NB_v1360': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                's-IntraSearchP-v1360',
                {
                    'k': 'ref',
                    't': 'ReselectionThreshold_NB_v1360',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'IntraFreqCellReselectionInfo_NB_v1430': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'powerClass14dBm-Offset-r14',
                {
                    'k': 'enum',
                    'names': ['dB-6', 'dB-3', 'dB3', 'dB6', 'dB9', 'dB12'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ce-AuthorisationOffset-r14',
                {
                    'k': 'enum',
                    'names': ['dB5', 'dB10', 'dB15', 'dB20', 'dB25', 'dB30', 'dB35'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'IntraFreqExcludedCellList': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PhysCellIdRange',
        },
    },
    'IntraFreqNeighCellInfo': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'physCellId',
                {
                    'k': 'ref',
                    't': 'PhysCellId',
                },
                False,
                None,
            ],
            [
                'q-OffsetCell',
                {
                    'k': 'ref',
                    't': 'Q_OffsetRange',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'IntraFreqNeighCellInfo_NB_v1530': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nsss-RRM-Config-r15',
                {
                    'k': 'ref',
                    't': 'NSSS_RRM_Config_NB_r15',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'IntraFreqNeighCellList': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'IntraFreqNeighCellInfo',
        },
    },
    'IntraFreqNeighCellList_NB_v1530': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'IntraFreqNeighCellInfo_NB_v1530',
        },
    },
    'MBMS_SAI_InterFreqList_NB_r14': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'MBMS_SAI_InterFreq_NB_r14',
        },
    },
    'MBMS_SAI_InterFreq_NB_r14': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'dl-CarrierFreq-r14',
                {
                    'k': 'ref',
                    't': 'CarrierFreq_NB_r13',
                },
                False,
                None,
            ],
            [
                'mbms-SAI-List-r14',
                {
                    'k': 'ref',
                    't': 'MBMS_SAI_List_r11',
                },
                False,
                None,
            ],
            [
                'multiBandInfoList-r14',
                {
                    'k': 'ref',
                    't': 'AdditionalBandInfoList_NB_r14',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'MBMS_SAI_List_r11': {
        'k': 'seqof',
        'size': [1, 64],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'MBMS_SAI_r11',
        },
    },
    'MBMS_SAI_r11': {
        'k': 'int',
        'lb': 0,
        'ub': 65535,
        'ext': False,
    },
    'MCC': {
        'k': 'seqof',
        'size': [3, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'MCC_MNC_Digit',
        },
    },
    'MCC_MNC_Digit': {
        'k': 'int',
        'lb': 0,
        'ub': 9,
        'ext': False,
    },
    'MNC': {
        'k': 'seqof',
        'size': [2, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'MCC_MNC_Digit',
        },
    },
    'MasterInformationBlock_NB': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'systemFrameNumber-MSB-r13',
                {
                    'k': 'bits',
                    'size': [4, 4],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'hyperSFN-LSB-r13',
                {
                    'k': 'bits',
                    'size': [2, 2],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'schedulingInfoSIB1-r13',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 15,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'systemInfoValueTag-r13',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 31,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'ab-Enabled-r13',
                {
                    'k': 'bool',
                },
                False,
                None,
            ],
            [
                'operationModeInfo-r13',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'inband-SamePCI-r13',
                            {
                                'k': 'ref',
                                't': 'Inband_SamePCI_NB_r13',
                            },
                        ],
                        [
                            'inband-DifferentPCI-r13',
                            {
                                'k': 'ref',
                                't': 'Inband_DifferentPCI_NB_r13',
                            },
                        ],
                        [
                            'guardband-r13',
                            {
                                'k': 'ref',
                                't': 'Guardband_NB_r13',
                            },
                        ],
                        [
                            'standalone-r13',
                            {
                                'k': 'ref',
                                't': 'Standalone_NB_r13',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'additionalTransmissionSIB1-r15',
                {
                    'k': 'bool',
                },
                False,
                None,
            ],
            [
                'ab-Enabled-5GC-r16',
                {
                    'k': 'bool',
                },
                False,
                None,
            ],
            [
                'partEARFCN-r17',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'spare',
                            {
                                'k': 'bits',
                                'size': [2, 2],
                                'ext': False,
                            },
                        ],
                        [
                            'earfcn-LSB',
                            {
                                'k': 'bits',
                                'size': [2, 2],
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'spare',
                {
                    'k': 'bits',
                    'size': [6, 6],
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'MultiBandInfoList_NB_r13': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'MultiBandInfo_NB_r13',
        },
    },
    'MultiBandInfo_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'freqBandIndicator-r13',
                {
                    'k': 'ref',
                    't': 'FreqBandIndicator_NB_r13',
                },
                True,
                None,
            ],
            [
                'freqBandInfo-r13',
                {
                    'k': 'ref',
                    't': 'NS_PmaxList_NB_r13',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPDCCH_SC_MCCH_Config_NB_r14': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'npdcch-NumRepetitions-SC-MCCH-r14',
                {
                    'k': 'enum',
                    'names': [
                        'r1',
                        'r2',
                        'r4',
                        'r8',
                        'r16',
                        'r32',
                        'r64',
                        'r128',
                        'r256',
                        'r512',
                        'r1024',
                        'r2048',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'npdcch-StartSF-SC-MCCH-r14',
                {
                    'k': 'enum',
                    'names': ['v1dot5', 'v2', 'v4', 'v8', 'v16', 'v32', 'v48', 'v64'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'npdcch-Offset-SC-MCCH-r14',
                {
                    'k': 'enum',
                    'names': [
                        'zero',
                        'oneEighth',
                        'oneQuarter',
                        'threeEighth',
                        'oneHalf',
                        'fiveEighth',
                        'threeQuarter',
                        'sevenEighth',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPDSCH_ConfigCommon_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nrs-Power-r13',
                {
                    'k': 'int',
                    'lb': -60,
                    'ub': 50,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ConfigSIB_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-CP-Length-r13',
                {
                    'k': 'enum',
                    'names': ['us66dot7', 'us266dot7'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'rsrp-ThresholdsPrachInfoList-r13',
                {
                    'k': 'ref',
                    't': 'RSRP_ThresholdsNPRACH_InfoList_NB_r13',
                },
                True,
                None,
            ],
            [
                'nprach-ParametersList-r13',
                {
                    'k': 'ref',
                    't': 'NPRACH_ParametersList_NB_r13',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ConfigSIB_NB_v1330': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-ParametersList-v1330',
                {
                    'k': 'ref',
                    't': 'NPRACH_ParametersList_NB_v1330',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ConfigSIB_NB_v1450': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'maxNumPreambleAttemptCE-r14',
                {
                    'k': 'enum',
                    'names': ['n3', 'n4', 'n5', 'n6', 'n7', 'n8', 'n10', 'spare1'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ConfigSIB_NB_v1530': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'tdd-Parameters-r15',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nprach-PreambleFormat-r15',
                            {
                                'k': 'enum',
                                'names': ['fmt0', 'fmt1', 'fmt2', 'fmt0-a', 'fmt1-a'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'dummy',
                            {
                                'k': 'enum',
                                'names': [
                                    'n1',
                                    'n2',
                                    'n4',
                                    'n8',
                                    'n16',
                                    'n32',
                                    'n64',
                                    'n128',
                                    'n256',
                                    'n512',
                                    'n1024',
                                ],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'nprach-ParametersListTDD-r15',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ParametersListTDD_NB_r15',
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'fmt2-Parameters-r15',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nprach-ParametersListFmt2-r15',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ParametersListFmt2_NB_r15',
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-ParametersListFmt2EDT-r15',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ParametersListFmt2_NB_r15',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'edt-Parameters-r15',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'edt-SmallTBS-Subset-r15',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'edt-TBS-InfoList-r15',
                            {
                                'k': 'ref',
                                't': 'EDT_TBS_InfoList_NB_r15',
                            },
                            False,
                            None,
                        ],
                        [
                            'nprach-ParametersListEDT-r15',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ParametersList_NB_r14',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ConfigSIB_NB_v1550': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'tdd-Parameters-v1550',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nprach-ParametersListTDD-v1550',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ParametersListTDD_NB_v1550',
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ParametersFmt2_NB_r15': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-Parameters-r15',
                {
                    'k': 'seq',
                    'ext': True,
                    'comp': [
                        [
                            'nprach-Periodicity-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'ms40',
                                    'ms80',
                                    'ms160',
                                    'ms320',
                                    'ms640',
                                    'ms1280',
                                    'ms2560',
                                    'ms5120',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-StartTime-r15',
                            {
                                'k': 'enum',
                                'names': ['ms8', 'ms16', 'ms32', 'ms64', 'ms128', 'ms256', 'ms512', 'ms1024'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-SubcarrierOffset-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'n0',
                                    'n36',
                                    'n72',
                                    'n108',
                                    'n6',
                                    'n54',
                                    'n102',
                                    'n42',
                                    'n78',
                                    'n90',
                                    'n12',
                                    'n24',
                                    'n48',
                                    'n84',
                                    'n60',
                                    'n18',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-NumSubcarriers-r15',
                            {
                                'k': 'enum',
                                'names': ['n36', 'n72', 'n108', 'n144'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-SubcarrierMSG3-RangeStart-r15',
                            {
                                'k': 'enum',
                                'names': ['zero', 'oneThird', 'twoThird', 'one'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-NumRepetitions-RA-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'r1',
                                    'r2',
                                    'r4',
                                    'r8',
                                    'r16',
                                    'r32',
                                    'r64',
                                    'r128',
                                    'r256',
                                    'r512',
                                    'r1024',
                                    'r2048',
                                    'spare4',
                                    'spare3',
                                    'spare2',
                                    'spare1',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-StartSF-CSS-RA-r15',
                            {
                                'k': 'enum',
                                'names': ['v1dot5', 'v2', 'v4', 'v8', 'v16', 'v32', 'v48', 'v64'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-Offset-RA-r15',
                            {
                                'k': 'enum',
                                'names': ['zero', 'oneEighth', 'oneFourth', 'threeEighth'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-NumCBRA-StartSubcarriers-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'n24',
                                    'n30',
                                    'n33',
                                    'n36',
                                    'n60',
                                    'n66',
                                    'n69',
                                    'n72',
                                    'n96',
                                    'n102',
                                    'n105',
                                    'n108',
                                    'n120',
                                    'n132',
                                    'n138',
                                    'n144',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-CarrierIndex-r15',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 15,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ParametersListFmt2_NB_r15': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NPRACH_ParametersFmt2_NB_r15',
        },
    },
    'NPRACH_ParametersListTDD_NB_r15': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NPRACH_ParametersTDD_NB_r15',
        },
    },
    'NPRACH_ParametersListTDD_NB_v1550': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NPRACH_ParametersTDD_NB_v1550',
        },
    },
    'NPRACH_ParametersList_NB_r13': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NPRACH_Parameters_NB_r13',
        },
    },
    'NPRACH_ParametersList_NB_r14': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NPRACH_Parameters_NB_r14',
        },
    },
    'NPRACH_ParametersList_NB_v1330': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NPRACH_Parameters_NB_v1330',
        },
    },
    'NPRACH_ParametersTDD_NB_r15': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-Parameters-r15',
                {
                    'k': 'seq',
                    'ext': True,
                    'comp': [
                        [
                            'nprach-Periodicity-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'ms80',
                                    'ms160',
                                    'ms320',
                                    'ms640',
                                    'ms1280',
                                    'ms2560',
                                    'ms5120',
                                    'ms10240',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-StartTime-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'ms10',
                                    'ms20',
                                    'ms40',
                                    'ms80',
                                    'ms160',
                                    'ms320',
                                    'ms640',
                                    'ms1280',
                                    'ms2560',
                                    'ms5120',
                                    'spare6',
                                    'spare5',
                                    'spare4',
                                    'spare3',
                                    'spare2',
                                    'spare1',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-SubcarrierOffset-r15',
                            {
                                'k': 'enum',
                                'names': ['n0', 'n12', 'n24', 'n36', 'n2', 'n18', 'n34', 'spare1'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-NumSubcarriers-r15',
                            {
                                'k': 'enum',
                                'names': ['n12', 'n24', 'n36', 'n48'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-SubcarrierMSG3-RangeStart-r15',
                            {
                                'k': 'enum',
                                'names': ['zero', 'oneThird', 'twoThird', 'one'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-NumRepetitions-RA-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'r1',
                                    'r2',
                                    'r4',
                                    'r8',
                                    'r16',
                                    'r32',
                                    'r64',
                                    'r128',
                                    'r256',
                                    'r512',
                                    'r1024',
                                    'r2048',
                                    'spare4',
                                    'spare3',
                                    'spare2',
                                    'spare1',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-StartSF-CSS-RA-r15',
                            {
                                'k': 'enum',
                                'names': ['v4', 'v8', 'v16', 'v32', 'v48', 'v64', 'v96', 'v128'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-Offset-RA-r15',
                            {
                                'k': 'enum',
                                'names': ['zero', 'oneEighth', 'oneFourth', 'threeEighth'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-NumCBRA-StartSubcarriers-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'n8',
                                    'n10',
                                    'n11',
                                    'n12',
                                    'n20',
                                    'n22',
                                    'n23',
                                    'n24',
                                    'n32',
                                    'n34',
                                    'n35',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n46',
                                    'n48',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ParametersTDD_NB_v1550': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'maxNumPreambleAttemptCE-v1550',
                {
                    'k': 'enum',
                    'names': ['n3', 'n4', 'n5', 'n6', 'n7', 'n8', 'n10', 'spare1'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'numRepetitionsPerPreambleAttempt-v1550',
                {
                    'k': 'enum',
                    'names': [
                        'n1',
                        'n2',
                        'n4',
                        'n8',
                        'n16',
                        'n32',
                        'n64',
                        'n128',
                        'n256',
                        'n512',
                        'n1024',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_Parameters_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-Periodicity-r13',
                {
                    'k': 'enum',
                    'names': [
                        'ms40',
                        'ms80',
                        'ms160',
                        'ms240',
                        'ms320',
                        'ms640',
                        'ms1280',
                        'ms2560',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'nprach-StartTime-r13',
                {
                    'k': 'enum',
                    'names': ['ms8', 'ms16', 'ms32', 'ms64', 'ms128', 'ms256', 'ms512', 'ms1024'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'nprach-SubcarrierOffset-r13',
                {
                    'k': 'enum',
                    'names': ['n0', 'n12', 'n24', 'n36', 'n2', 'n18', 'n34', 'spare1'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'nprach-NumSubcarriers-r13',
                {
                    'k': 'enum',
                    'names': ['n12', 'n24', 'n36', 'n48'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'nprach-SubcarrierMSG3-RangeStart-r13',
                {
                    'k': 'enum',
                    'names': ['zero', 'oneThird', 'twoThird', 'one'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'maxNumPreambleAttemptCE-r13',
                {
                    'k': 'enum',
                    'names': ['n3', 'n4', 'n5', 'n6', 'n7', 'n8', 'n10', 'spare1'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'numRepetitionsPerPreambleAttempt-r13',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n4', 'n8', 'n16', 'n32', 'n64', 'n128'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'npdcch-NumRepetitions-RA-r13',
                {
                    'k': 'enum',
                    'names': [
                        'r1',
                        'r2',
                        'r4',
                        'r8',
                        'r16',
                        'r32',
                        'r64',
                        'r128',
                        'r256',
                        'r512',
                        'r1024',
                        'r2048',
                        'spare4',
                        'spare3',
                        'spare2',
                        'spare1',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'npdcch-StartSF-CSS-RA-r13',
                {
                    'k': 'enum',
                    'names': ['v1dot5', 'v2', 'v4', 'v8', 'v16', 'v32', 'v48', 'v64'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'npdcch-Offset-RA-r13',
                {
                    'k': 'enum',
                    'names': ['zero', 'oneEighth', 'oneFourth', 'threeEighth'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_Parameters_NB_r14': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-Parameters-r14',
                {
                    'k': 'seq',
                    'ext': True,
                    'comp': [
                        [
                            'nprach-Periodicity-r14',
                            {
                                'k': 'enum',
                                'names': [
                                    'ms40',
                                    'ms80',
                                    'ms160',
                                    'ms240',
                                    'ms320',
                                    'ms640',
                                    'ms1280',
                                    'ms2560',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-StartTime-r14',
                            {
                                'k': 'enum',
                                'names': ['ms8', 'ms16', 'ms32', 'ms64', 'ms128', 'ms256', 'ms512', 'ms1024'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-SubcarrierOffset-r14',
                            {
                                'k': 'enum',
                                'names': ['n0', 'n12', 'n24', 'n36', 'n2', 'n18', 'n34', 'spare1'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-NumSubcarriers-r14',
                            {
                                'k': 'enum',
                                'names': ['n12', 'n24', 'n36', 'n48'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-SubcarrierMSG3-RangeStart-r14',
                            {
                                'k': 'enum',
                                'names': ['zero', 'oneThird', 'twoThird', 'one'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-NumRepetitions-RA-r14',
                            {
                                'k': 'enum',
                                'names': [
                                    'r1',
                                    'r2',
                                    'r4',
                                    'r8',
                                    'r16',
                                    'r32',
                                    'r64',
                                    'r128',
                                    'r256',
                                    'r512',
                                    'r1024',
                                    'r2048',
                                    'spare4',
                                    'spare3',
                                    'spare2',
                                    'spare1',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-StartSF-CSS-RA-r14',
                            {
                                'k': 'enum',
                                'names': ['v1dot5', 'v2', 'v4', 'v8', 'v16', 'v32', 'v48', 'v64'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-Offset-RA-r14',
                            {
                                'k': 'enum',
                                'names': ['zero', 'oneEighth', 'oneFourth', 'threeEighth'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'nprach-NumCBRA-StartSubcarriers-r14',
                            {
                                'k': 'enum',
                                'names': [
                                    'n8',
                                    'n10',
                                    'n11',
                                    'n12',
                                    'n20',
                                    'n22',
                                    'n23',
                                    'n24',
                                    'n32',
                                    'n34',
                                    'n35',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n46',
                                    'n48',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npdcch-CarrierIndex-r14',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 15,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_Parameters_NB_v1330': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-NumCBRA-StartSubcarriers-r13',
                {
                    'k': 'enum',
                    'names': [
                        'n8',
                        'n10',
                        'n11',
                        'n12',
                        'n20',
                        'n22',
                        'n23',
                        'n24',
                        'n32',
                        'n34',
                        'n35',
                        'n36',
                        'n40',
                        'n44',
                        'n46',
                        'n48',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_ProbabilityAnchorList_NB_r14': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NPRACH_ProbabilityAnchor_NB_r14',
        },
    },
    'NPRACH_ProbabilityAnchor_NB_r14': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-ProbabilityAnchor-r14',
                {
                    'k': 'enum',
                    'names': [
                        'zero',
                        'oneSixteenth',
                        'oneFifteenth',
                        'oneFourteenth',
                        'oneThirteenth',
                        'oneTwelfth',
                        'oneEleventh',
                        'oneTenth',
                        'oneNinth',
                        'oneEighth',
                        'oneSeventh',
                        'oneSixth',
                        'oneFifth',
                        'oneFourth',
                        'oneThird',
                        'oneHalf',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_TxDurationFmt01_NB_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-TxDurationFmt01-r17',
                {
                    'k': 'enum',
                    'names': ['n2', 'n4', 'n8', 'n16', 'n32', 'n64'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPRACH_TxDurationFmt2_NB_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nprach-TxDurationFmt2-r17',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n4', 'n8', 'n16'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPUSCH_ConfigCommon_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ack-NACK-NumRepetitions-Msg4-r13',
                {
                    'k': 'seqof',
                    'size': [1, 3],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'ACK_NACK_NumRepetitions_NB_r13',
                    },
                },
                False,
                None,
            ],
            [
                'srs-SubframeConfig-r13',
                {
                    'k': 'enum',
                    'names': [
                        'sc0',
                        'sc1',
                        'sc2',
                        'sc3',
                        'sc4',
                        'sc5',
                        'sc6',
                        'sc7',
                        'sc8',
                        'sc9',
                        'sc10',
                        'sc11',
                        'sc12',
                        'sc13',
                        'sc14',
                        'sc15',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'dmrs-Config-r13',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'threeTone-BaseSequence-r13',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 12,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'threeTone-CyclicShift-r13',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 2,
                                'ext': False,
                            },
                            False,
                            None,
                        ],
                        [
                            'sixTone-BaseSequence-r13',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 14,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'sixTone-CyclicShift-r13',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 3,
                                'ext': False,
                            },
                            False,
                            None,
                        ],
                        [
                            'twelveTone-BaseSequence-r13',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 30,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'ul-ReferenceSignalsNPUSCH-r13',
                {
                    'k': 'ref',
                    't': 'UL_ReferenceSignalsNPUSCH_NB_r13',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NPUSCH_TxDuration_NB_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'npusch-TxDuration-r17',
                {
                    'k': 'enum',
                    'names': ['ms2', 'ms4', 'ms8', 'ms16', 'ms32', 'ms64', 'ms128', 'ms256'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NRSRP_Range_NB_r14': {
        'k': 'int',
        'lb': 0,
        'ub': 113,
        'ext': False,
    },
    'NSSS_RRM_Config_NB_r15': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nsss-RRM-PowerOffset-r15',
                {
                    'k': 'enum',
                    'names': ['dB-3', 'db0', 'dB3'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'nsss-NumOccDiffPrecoders-r15',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n4', 'n8'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NS_PmaxList_NB_r13': {
        'k': 'seqof',
        'size': [1, 4],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NS_PmaxValue_NB_r13',
        },
    },
    'NS_PmaxValue_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'additionalPmax-r13',
                {
                    'k': 'ref',
                    't': 'P_Max',
                },
                True,
                None,
            ],
            [
                'additionalSpectrumEmission-r13',
                {
                    'k': 'ref',
                    't': 'AdditionalSpectrumEmission',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NeighSatelliteInfoList_r18': {
        'k': 'seqof',
        'size': [1, 4],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NeighSatelliteInfo_r18',
        },
    },
    'NeighSatelliteInfo_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'satelliteId-r18',
                {
                    'k': 'ref',
                    't': 'SatelliteId_r18',
                },
                False,
                None,
            ],
            [
                'ephemerisInfo-r18',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'stateVectors-r18',
                            {
                                'k': 'ref',
                                't': 'EphemerisStateVectors_r17',
                            },
                        ],
                        [
                            'orbitalParameters-r18',
                            {
                                'k': 'ref',
                                't': 'EphemerisOrbitalParameters_r17',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'nta-CommonParameters-r18',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nta-Common-r18',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 8316827,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'nta-CommonDrift-r18',
                            {
                                'k': 'int',
                                'lb': -261935,
                                'ub': 261935,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'nta-CommonDriftVariation-r18',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 29479,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'epochTime-r18',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'startSFN-r18',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1023,
                                'ext': False,
                            },
                            False,
                            None,
                        ],
                        [
                            'startSubFrame-r18',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 9,
                                'ext': False,
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'k-Mac-r18',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 512,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                't-ServiceStartNeigh-r18',
                {
                    'k': 'ref',
                    't': 'TimeOffsetUTC_r17',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PCCH_Config_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'defaultPagingCycle-r13',
                {
                    'k': 'enum',
                    'names': ['rf128', 'rf256', 'rf512', 'rf1024'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'nB-r13',
                {
                    'k': 'enum',
                    'names': [
                        'fourT',
                        'twoT',
                        'oneT',
                        'halfT',
                        'quarterT',
                        'one8thT',
                        'one16thT',
                        'one32ndT',
                        'one64thT',
                        'one128thT',
                        'one256thT',
                        'one512thT',
                        'one1024thT',
                        'spare3',
                        'spare2',
                        'spare1',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'npdcch-NumRepetitionPaging-r13',
                {
                    'k': 'enum',
                    'names': [
                        'r1',
                        'r2',
                        'r4',
                        'r8',
                        'r16',
                        'r32',
                        'r64',
                        'r128',
                        'r256',
                        'r512',
                        'r1024',
                        'r2048',
                        'spare4',
                        'spare3',
                        'spare2',
                        'spare1',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'PCCH_Config_NB_r14': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'npdcch-NumRepetitionPaging-r14',
                {
                    'k': 'enum',
                    'names': [
                        'r1',
                        'r2',
                        'r4',
                        'r8',
                        'r16',
                        'r32',
                        'r64',
                        'r128',
                        'r256',
                        'r512',
                        'r1024',
                        'r2048',
                        'spare4',
                        'spare3',
                        'spare2',
                        'spare1',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'pagingWeight-r14',
                {
                    'k': 'ref',
                    't': 'PagingWeight_NB_r14',
                },
                False,
                'w1',
            ],
        ],
        'extadd': [],
    },
    'PCCH_Config_NB_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'cbp-Index-r17',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 2,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'npdcch-NumRepetitionPaging-r17',
                {
                    'k': 'enum',
                    'names': ['r1', 'r2', 'r4', 'r8', 'r16', 'r32', 'r64', 'r128'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'pagingWeight-r17',
                {
                    'k': 'ref',
                    't': 'PagingWeight_NB_r14',
                },
                False,
                'w1',
            ],
        ],
        'extadd': [],
    },
    'PLMN_Identity': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'mcc',
                {
                    'k': 'ref',
                    't': 'MCC',
                },
                True,
                None,
            ],
            [
                'mnc',
                {
                    'k': 'ref',
                    't': 'MNC',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'PLMN_IdentityInfo_5GC_NB_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'plmn-Identity-5GC-r16',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'plmn-Identity-r16',
                            {
                                'k': 'ref',
                                't': 'PLMN_Identity',
                            },
                        ],
                        [
                            'plmn-Index-r16',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 6,
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'cellReservedForOperatorUse-r16',
                {
                    'k': 'enum',
                    'names': ['reserved', 'notReserved'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'ng-U-DataTransfer-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'up-CIoT-5GS-Optimisation-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PLMN_IdentityInfo_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'plmn-Identity-r13',
                {
                    'k': 'ref',
                    't': 'PLMN_Identity',
                },
                False,
                None,
            ],
            [
                'cellReservedForOperatorUse-r13',
                {
                    'k': 'enum',
                    'names': ['reserved', 'notReserved'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'attachWithoutPDN-Connectivity-r13',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PLMN_IdentityInfo_NB_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'trackingAreaList-r17',
                {
                    'k': 'ref',
                    't': 'TrackingAreaList_NB_r17',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PLMN_IdentityList_5GC_NB_r16': {
        'k': 'seqof',
        'size': [1, 6],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PLMN_IdentityInfo_5GC_NB_r16',
        },
    },
    'PLMN_IdentityList_NB_r13': {
        'k': 'seqof',
        'size': [1, 6],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PLMN_IdentityInfo_NB_r13',
        },
    },
    'PLMN_IdentityList_NB_v1700': {
        'k': 'seqof',
        'size': [1, 6],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PLMN_IdentityInfo_NB_v1700',
        },
    },
    'P_Max': {
        'k': 'int',
        'lb': -30,
        'ub': 33,
        'ext': False,
    },
    'PagingWeight_NB_r14': {
        'k': 'enum',
        'names': [
            'w1',
            'w2',
            'w3',
            'w4',
            'w5',
            'w6',
            'w7',
            'w8',
            'w9',
            'w10',
            'w11',
            'w12',
            'w13',
            'w14',
            'w15',
            'w16',
        ],
        'ext': None,
    },
    'PhysCellId': {
        'k': 'int',
        'lb': 0,
        'ub': 503,
        'ext': False,
    },
    'PhysCellIdRange': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'start',
                {
                    'k': 'ref',
                    't': 'PhysCellId',
                },
                False,
                None,
            ],
            [
                'range',
                {
                    'k': 'enum',
                    'names': [
                        'n4',
                        'n8',
                        'n12',
                        'n16',
                        'n24',
                        'n32',
                        'n48',
                        'n64',
                        'n84',
                        'n96',
                        'n128',
                        'n168',
                        'n252',
                        'n504',
                        'spare2',
                        'spare1',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PositionStateVector_r17': {
        'k': 'int',
        'lb': -33554432,
        'ub': 33554431,
        'ext': False,
    },
    'PowerRampingParameters': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'powerRampingStep',
                {
                    'k': 'enum',
                    'names': ['dB0', 'dB2', 'dB4', 'dB6'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'preambleInitialReceivedTargetPower',
                {
                    'k': 'enum',
                    'names': [
                        'dBm-120',
                        'dBm-118',
                        'dBm-116',
                        'dBm-114',
                        'dBm-112',
                        'dBm-110',
                        'dBm-108',
                        'dBm-106',
                        'dBm-104',
                        'dBm-102',
                        'dBm-100',
                        'dBm-98',
                        'dBm-96',
                        'dBm-94',
                        'dBm-92',
                        'dBm-90',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'PowerRampingParameters_NB_v1450': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'preambleInitialReceivedTargetPower-v1450',
                {
                    'k': 'enum',
                    'names': [
                        'dBm-130',
                        'dBm-128',
                        'dBm-126',
                        'dBm-124',
                        'dBm-122',
                        'dBm-88',
                        'dBm-86',
                        'dBm-84',
                        'dBm-82',
                        'dBm-80',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'powerRampingParametersCE1-r14',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'powerRampingStepCE1-r14',
                            {
                                'k': 'enum',
                                'names': ['dB0', 'dB2', 'dB4', 'dB6'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'preambleInitialReceivedTargetPowerCE1-r14',
                            {
                                'k': 'enum',
                                'names': [
                                    'dBm-130',
                                    'dBm-128',
                                    'dBm-126',
                                    'dBm-124',
                                    'dBm-122',
                                    'dBm-120',
                                    'dBm-118',
                                    'dBm-116',
                                    'dBm-114',
                                    'dBm-112',
                                    'dBm-110',
                                    'dBm-108',
                                    'dBm-106',
                                    'dBm-104',
                                    'dBm-102',
                                    'dBm-100',
                                    'dBm-98',
                                    'dBm-96',
                                    'dBm-94',
                                    'dBm-92',
                                    'dBm-90',
                                    'dBm-88',
                                    'dBm-86',
                                    'dBm-84',
                                    'dBm-82',
                                    'dBm-80',
                                ],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PreambleTransMax': {
        'k': 'enum',
        'names': [
            'n3',
            'n4',
            'n5',
            'n6',
            'n7',
            'n8',
            'n10',
            'n20',
            'n50',
            'n100',
            'n200',
        ],
        'ext': None,
    },
    'Q_OffsetRange': {
        'k': 'enum',
        'names': [
            'dB-24',
            'dB-22',
            'dB-20',
            'dB-18',
            'dB-16',
            'dB-14',
            'dB-12',
            'dB-10',
            'dB-8',
            'dB-6',
            'dB-5',
            'dB-4',
            'dB-3',
            'dB-2',
            'dB-1',
            'dB0',
            'dB1',
            'dB2',
            'dB3',
            'dB4',
            'dB5',
            'dB6',
            'dB8',
            'dB10',
            'dB12',
            'dB14',
            'dB16',
            'dB18',
            'dB20',
            'dB22',
            'dB24',
        ],
        'ext': None,
    },
    'Q_QualMin_r9': {
        'k': 'int',
        'lb': -34,
        'ub': -3,
        'ext': False,
    },
    'Q_RxLevMin': {
        'k': 'int',
        'lb': -70,
        'ub': -22,
        'ext': False,
    },
    'RACH_ConfigCommon_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'preambleTransMax-CE-r13',
                {
                    'k': 'ref',
                    't': 'PreambleTransMax',
                },
                False,
                None,
            ],
            [
                'powerRampingParameters-r13',
                {
                    'k': 'ref',
                    't': 'PowerRampingParameters',
                },
                False,
                None,
            ],
            [
                'rach-InfoList-r13',
                {
                    'k': 'ref',
                    't': 'RACH_InfoList_NB_r13',
                },
                False,
                None,
            ],
            [
                'connEstFailOffset-r13',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 15,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['powerRampingParameters-v1450'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'powerRampingParameters-v1450',
                            {
                                'k': 'ref',
                                't': 'PowerRampingParameters_NB_v1450',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['rach-InfoList-v1530'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'rach-InfoList-v1530',
                            {
                                'k': 'ref',
                                't': 'RACH_InfoList_NB_v1530',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'RACH_InfoList_NB_r13': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'RACH_Info_NB_r13',
        },
    },
    'RACH_InfoList_NB_v1530': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'RACH_Info_NB_v1530',
        },
    },
    'RACH_Info_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ra-ResponseWindowSize-r13',
                {
                    'k': 'enum',
                    'names': ['pp2', 'pp3', 'pp4', 'pp5', 'pp6', 'pp7', 'pp8', 'pp10'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'mac-ContentionResolutionTimer-r13',
                {
                    'k': 'enum',
                    'names': ['pp1', 'pp2', 'pp3', 'pp4', 'pp8', 'pp16', 'pp32', 'pp64'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'RACH_Info_NB_v1530': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'mac-ContentionResolutionTimer-r15',
                {
                    'k': 'enum',
                    'names': ['pp1', 'pp2', 'pp3', 'pp4', 'pp8', 'pp16', 'pp32', 'pp64'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'RSRP_Range': {
        'k': 'int',
        'lb': 0,
        'ub': 97,
        'ext': False,
    },
    'RSRP_ThresholdsNPRACH_InfoList_NB_r13': {
        'k': 'seqof',
        'size': [1, 2],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'RSRP_Range',
        },
    },
    'RadioResourceConfigCommonSIB_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'rach-ConfigCommon-r13',
                {
                    'k': 'ref',
                    't': 'RACH_ConfigCommon_NB_r13',
                },
                False,
                None,
            ],
            [
                'bcch-Config-r13',
                {
                    'k': 'ref',
                    't': 'BCCH_Config_NB_r13',
                },
                False,
                None,
            ],
            [
                'pcch-Config-r13',
                {
                    'k': 'ref',
                    't': 'PCCH_Config_NB_r13',
                },
                False,
                None,
            ],
            [
                'nprach-Config-r13',
                {
                    'k': 'ref',
                    't': 'NPRACH_ConfigSIB_NB_r13',
                },
                False,
                None,
            ],
            [
                'npdsch-ConfigCommon-r13',
                {
                    'k': 'ref',
                    't': 'NPDSCH_ConfigCommon_NB_r13',
                },
                False,
                None,
            ],
            [
                'npusch-ConfigCommon-r13',
                {
                    'k': 'ref',
                    't': 'NPUSCH_ConfigCommon_NB_r13',
                },
                False,
                None,
            ],
            [
                'dl-Gap-r13',
                {
                    'k': 'ref',
                    't': 'DL_GapConfig_NB_r13',
                },
                True,
                None,
            ],
            [
                'uplinkPowerControlCommon-r13',
                {
                    'k': 'ref',
                    't': 'UplinkPowerControlCommon_NB_r13',
                },
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['nprach-Config-v1330'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nprach-Config-v1330',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ConfigSIB_NB_v1330',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['nprach-Config-v1450'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nprach-Config-v1450',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ConfigSIB_NB_v1450',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['nprach-Config-v1530', 'dl-Gap-v1530', 'wus-Config-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nprach-Config-v1530',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ConfigSIB_NB_v1530',
                            },
                            True,
                            None,
                        ],
                        [
                            'dl-Gap-v1530',
                            {
                                'k': 'ref',
                                't': 'DL_GapConfig_NB_v1530',
                            },
                            True,
                            None,
                        ],
                        [
                            'wus-Config-r15',
                            {
                                'k': 'ref',
                                't': 'WUS_Config_NB_r15',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['nprach-Config-v1550'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nprach-Config-v1550',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ConfigSIB_NB_v1550',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': [
                    'gwus-Config-r16',
                    'nrs-NonAnchorConfig-r16',
                    'ue-SpecificDRX-CycleMin-r16',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'gwus-Config-r16',
                            {
                                'k': 'ref',
                                't': 'GWUS_Config_NB_r16',
                            },
                            True,
                            None,
                        ],
                        [
                            'nrs-NonAnchorConfig-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'ue-SpecificDRX-CycleMin-r16',
                            {
                                'k': 'enum',
                                'names': ['rf32', 'rf64', 'rf128', 'rf256', 'rf512', 'rf1024'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['ntn-ConfigCommon-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ntn-ConfigCommon-r17',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'ta-Report-r17',
                                        {
                                            'k': 'enum',
                                            'names': ['enabled'],
                                            'ext': None,
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        't318-r17',
                                        {
                                            'k': 'enum',
                                            'names': ['ms0', 'ms200', 'ms500', 'ms1000', 'ms2000', 'ms4000', 'ms8000'],
                                            'ext': None,
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'nprach-TxDurationFmt01-r17',
                                        {
                                            'k': 'ref',
                                            't': 'NPRACH_TxDurationFmt01_NB_r17',
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'nprach-TxDurationFmt2-r17',
                                        {
                                            'k': 'ref',
                                            't': 'NPRACH_TxDurationFmt2_NB_r17',
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'npusch-TxDuration-r17',
                                        {
                                            'k': 'ref',
                                            't': 'NPUSCH_TxDuration_NB_r17',
                                        },
                                        True,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'ReferenceLocation_r18': {
        'k': 'octets',
        'size': None,
        'ext': False,
        'containing': None,
    },
    'ReferenceTime_r15': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'refDays-r15',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 72999,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'refSeconds-r15',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 86399,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'refMilliSeconds-r15',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 999,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'refQuarterMicroSeconds-r15',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 3999,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'ReselectionThreshold': {
        'k': 'int',
        'lb': 0,
        'ub': 31,
        'ext': False,
    },
    'ReselectionThreshold_NB_v1360': {
        'k': 'int',
        'lb': 32,
        'ub': 63,
        'ext': False,
    },
    'SC_MCCH_SchedulingInfo_NB_r14': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'onDurationTimerSCPTM-r14',
                {
                    'k': 'enum',
                    'names': ['pp1', 'pp2', 'pp3', 'pp4', 'pp8', 'pp16', 'pp32', 'spare'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'drx-InactivityTimerSCPTM-r14',
                {
                    'k': 'enum',
                    'names': ['pp0', 'pp1', 'pp2', 'pp3', 'pp4', 'pp8', 'pp16', 'pp32'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'schedulingPeriodStartOffsetSCPTM-r14',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'sf10',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 9,
                                'ext': False,
                            },
                        ],
                        [
                            'sf20',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 19,
                                'ext': False,
                            },
                        ],
                        [
                            'sf32',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 31,
                                'ext': False,
                            },
                        ],
                        [
                            'sf40',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 39,
                                'ext': False,
                            },
                        ],
                        [
                            'sf64',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 63,
                                'ext': False,
                            },
                        ],
                        [
                            'sf80',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 79,
                                'ext': False,
                            },
                        ],
                        [
                            'sf128',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 127,
                                'ext': False,
                            },
                        ],
                        [
                            'sf160',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 159,
                                'ext': False,
                            },
                        ],
                        [
                            'sf256',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 255,
                                'ext': False,
                            },
                        ],
                        [
                            'sf320',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 319,
                                'ext': False,
                            },
                        ],
                        [
                            'sf512',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 511,
                                'ext': False,
                            },
                        ],
                        [
                            'sf640',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 639,
                                'ext': False,
                            },
                        ],
                        [
                            'sf1024',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1023,
                                'ext': False,
                            },
                        ],
                        [
                            'sf2048',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 2047,
                                'ext': False,
                            },
                        ],
                        [
                            'sf4096',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 4095,
                                'ext': False,
                            },
                        ],
                        [
                            'sf8192',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 8191,
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB_MappingInfo_NB_r13': {
        'k': 'seqof',
        'size': [0, 31],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SIB_Type_NB_r13',
        },
    },
    'SIB_MappingInfo_NB_v1530': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SIB_Type_NB_v1530',
        },
    },
    'SIB_Type_NB_r13': {
        'k': 'enum',
        'names': [
            'sibType3-NB-r13',
            'sibType4-NB-r13',
            'sibType5-NB-r13',
            'sibType14-NB-r13',
            'sibType16-NB-r13',
            'sibType15-NB-r14',
            'sibType20-NB-r14',
            'sibType22-NB-r14',
        ],
        'ext': None,
    },
    'SIB_Type_NB_v1530': {
        'k': 'enum',
        'names': [
            'sibType23-NB-r15',
            'sibType27-NB-r16',
            'sibType31-NB-r17',
            'sibType32-NB-r17',
            'sibType33-NB-r18',
            'spare3',
            'spare2',
            'spare1',
        ],
        'ext': None,
    },
    'SatelliteId_r18': {
        'k': 'int',
        'lb': 0,
        'ub': 255,
        'ext': False,
    },
    'SatelliteInfoList_NB_v1830': {
        'k': 'seqof',
        'size': [1, 4],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CarrierFreqList_NB_r18',
        },
    },
    'SatelliteInfoList_r17': {
        'k': 'seqof',
        'size': [1, 4],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SatelliteInfo_r17',
        },
    },
    'SatelliteInfoList_v1800': {
        'k': 'seqof',
        'size': [1, 4],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CarrierFreqList_v1800',
        },
    },
    'SatelliteInfo_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'satelliteId-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 255,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'serviceInfo-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'tle-EphemerisParameters-r17',
                            {
                                'k': 'ref',
                                't': 'TLE_EphemerisParameters_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            't-ServiceStart-r17',
                            {
                                'k': 'ref',
                                't': 'TimeOffsetUTC_r17',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'footprintInfo-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'referencePoint-r17',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'longitude-r17',
                                        {
                                            'k': 'int',
                                            'lb': -131072,
                                            'ub': 131071,
                                            'ext': False,
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'latitude-r17',
                                        {
                                            'k': 'int',
                                            'lb': -131072,
                                            'ub': 131071,
                                            'ext': False,
                                        },
                                        False,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'elevationAngles-r17',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'elevationAngleRight-r17',
                                        {
                                            'k': 'int',
                                            'lb': -14,
                                            'ub': 14,
                                            'ext': False,
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'elevationAngleLeft-r17',
                                        {
                                            'k': 'int',
                                            'lb': -14,
                                            'ub': 14,
                                            'ext': False,
                                        },
                                        True,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'radius-r17',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 256,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SchedulingInfoList_NB_r13': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SchedulingInfo_NB_r13',
        },
    },
    'SchedulingInfoList_NB_v1530': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SchedulingInfo_NB_v1530',
        },
    },
    'SchedulingInfo_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'si-Periodicity-r13',
                {
                    'k': 'enum',
                    'names': [
                        'rf64',
                        'rf128',
                        'rf256',
                        'rf512',
                        'rf1024',
                        'rf2048',
                        'rf4096',
                        'spare',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'si-RepetitionPattern-r13',
                {
                    'k': 'enum',
                    'names': ['every2ndRF', 'every4thRF', 'every8thRF', 'every16thRF'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'sib-MappingInfo-r13',
                {
                    'k': 'ref',
                    't': 'SIB_MappingInfo_NB_r13',
                },
                False,
                None,
            ],
            [
                'si-TB-r13',
                {
                    'k': 'enum',
                    'names': ['b56', 'b120', 'b208', 'b256', 'b328', 'b440', 'b552', 'b680'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SchedulingInfo_NB_v1530': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'sib-MappingInfo-v1530',
                {
                    'k': 'ref',
                    't': 'SIB_MappingInfo_NB_v1530',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'ServingSatelliteInfo_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'ephemerisInfo-r17',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'stateVectors',
                            {
                                'k': 'ref',
                                't': 'EphemerisStateVectors_r17',
                            },
                        ],
                        [
                            'orbitalParameters',
                            {
                                'k': 'ref',
                                't': 'EphemerisOrbitalParameters_r17',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'nta-CommonParameters-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nta-Common-r17',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 8316827,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'nta-CommonDrift-r17',
                            {
                                'k': 'int',
                                'lb': -261935,
                                'ub': 261935,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'nta-CommonDriftVariation-r17',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 29479,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'ul-SyncValidityDuration-r17',
                {
                    'k': 'enum',
                    'names': [
                        's5',
                        's10',
                        's15',
                        's20',
                        's25',
                        's30',
                        's35',
                        's40',
                        's45',
                        's50',
                        's55',
                        's60',
                        's120',
                        's180',
                        's240',
                        's900',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'epochTime-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'startSFN-r17',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1023,
                                'ext': False,
                            },
                            False,
                            None,
                        ],
                        [
                            'startSubFrame-r17',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 9,
                                'ext': False,
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'k-Offset-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1023,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'k-Mac-r17',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 512,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'ServingSatelliteInfo_v1820': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'satelliteId-r18',
                {
                    'k': 'ref',
                    't': 'SatelliteId_r18',
                },
                True,
                None,
            ],
            [
                'referenceLocation-r18',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'fixedReferenceLocation-r18',
                            {
                                'k': 'ref',
                                't': 'ReferenceLocation_r18',
                            },
                        ],
                        [
                            'movingReferenceLocation-r18',
                            {
                                'k': 'ref',
                                't': 'ReferenceLocation_r18',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'distanceThresh-r18',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 65535,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'Standalone_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'spare',
                {
                    'k': 'bits',
                    'size': [5, 5],
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInfoValueTagList_NB_r13': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SystemInfoValueTagSI_r13',
        },
    },
    'SystemInfoValueTagSI_r13': {
        'k': 'int',
        'lb': 0,
        'ub': 3,
        'ext': False,
    },
    'SystemInformationBlockType14_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'ab-Param-r13',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'ab-Common-r13',
                            {
                                'k': 'ref',
                                't': 'AB_Config_NB_r13',
                            },
                        ],
                        [
                            'ab-PerPLMN-List-r13',
                            {
                                'k': 'seqof',
                                'size': [1, 6],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'AB_ConfigPLMN_NB_r13',
                                },
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['ab-PerNRSRP-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ab-PerNRSRP-r15',
                            {
                                'k': 'enum',
                                'names': ['thresh1', 'thresh2'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['uac-Param-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'uac-Param-r16',
                            {
                                'k': 'ref',
                                't': 'UAC_Param_NB_r16',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformationBlockType15_NB_r14': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'mbms-SAI-IntraFreq-r14',
                {
                    'k': 'ref',
                    't': 'MBMS_SAI_List_r11',
                },
                True,
                None,
            ],
            [
                'mbms-SAI-InterFreqList-r14',
                {
                    'k': 'ref',
                    't': 'MBMS_SAI_InterFreqList_NB_r14',
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType16_NB_r13': {
        'k': 'ref',
        't': 'SystemInformationBlockType16_r11',
    },
    'SystemInformationBlockType16_r11': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'timeInfo-r11',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'timeInfoUTC-r11',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 549755813887,
                                'ext': False,
                            },
                            False,
                            None,
                        ],
                        [
                            'dayLightSavingTime-r11',
                            {
                                'k': 'bits',
                                'size': [2, 2],
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'leapSeconds-r11',
                            {
                                'k': 'int',
                                'lb': -127,
                                'ub': 128,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'localTimeOffset-r11',
                            {
                                'k': 'int',
                                'lb': -63,
                                'ub': 64,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['timeReferenceInfo-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'timeReferenceInfo-r15',
                            {
                                'k': 'ref',
                                't': 'TimeReferenceInfo_r15',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformationBlockType1_NB': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'hyperSFN-MSB-r13',
                {
                    'k': 'bits',
                    'size': [8, 8],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'cellAccessRelatedInfo-r13',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'plmn-IdentityList-r13',
                            {
                                'k': 'ref',
                                't': 'PLMN_IdentityList_NB_r13',
                            },
                            False,
                            None,
                        ],
                        [
                            'trackingAreaCode-r13',
                            {
                                'k': 'ref',
                                't': 'TrackingAreaCode',
                            },
                            False,
                            None,
                        ],
                        [
                            'cellIdentity-r13',
                            {
                                'k': 'ref',
                                't': 'CellIdentity',
                            },
                            False,
                            None,
                        ],
                        [
                            'cellBarred-r13',
                            {
                                'k': 'enum',
                                'names': ['barred', 'notBarred'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'intraFreqReselection-r13',
                            {
                                'k': 'enum',
                                'names': ['allowed', 'notAllowed'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'cellSelectionInfo-r13',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'q-RxLevMin-r13',
                            {
                                'k': 'ref',
                                't': 'Q_RxLevMin',
                            },
                            False,
                            None,
                        ],
                        [
                            'q-QualMin-r13',
                            {
                                'k': 'ref',
                                't': 'Q_QualMin_r9',
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'p-Max-r13',
                {
                    'k': 'ref',
                    't': 'P_Max',
                },
                True,
                None,
            ],
            [
                'freqBandIndicator-r13',
                {
                    'k': 'ref',
                    't': 'FreqBandIndicator_NB_r13',
                },
                False,
                None,
            ],
            [
                'freqBandInfo-r13',
                {
                    'k': 'ref',
                    't': 'NS_PmaxList_NB_r13',
                },
                True,
                None,
            ],
            [
                'multiBandInfoList-r13',
                {
                    'k': 'ref',
                    't': 'MultiBandInfoList_NB_r13',
                },
                True,
                None,
            ],
            [
                'downlinkBitmap-r13',
                {
                    'k': 'ref',
                    't': 'DL_Bitmap_NB_r13',
                },
                True,
                None,
            ],
            [
                'eutraControlRegionSize-r13',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n3'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'nrs-CRS-PowerOffset-r13',
                {
                    'k': 'enum',
                    'names': [
                        'dB-6',
                        'dB-4dot77',
                        'dB-3',
                        'dB-1dot77',
                        'dB0',
                        'dB1',
                        'dB1dot23',
                        'dB2',
                        'dB3',
                        'dB4',
                        'dB4dot23',
                        'dB5',
                        'dB6',
                        'dB7',
                        'dB8',
                        'dB9',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'schedulingInfoList-r13',
                {
                    'k': 'ref',
                    't': 'SchedulingInfoList_NB_r13',
                },
                False,
                None,
            ],
            [
                'si-WindowLength-r13',
                {
                    'k': 'enum',
                    'names': [
                        'ms160',
                        'ms320',
                        'ms480',
                        'ms640',
                        'ms960',
                        'ms1280',
                        'ms1600',
                        'spare1',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'si-RadioFrameOffset-r13',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 15,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'systemInfoValueTagList-r13',
                {
                    'k': 'ref',
                    't': 'SystemInfoValueTagList_NB_r13',
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SystemInformationBlockType1_NB_v1350',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType1_NB_v1350': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'cellSelectionInfo-v1350',
                {
                    'k': 'ref',
                    't': 'CellSelectionInfo_NB_v1350',
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SystemInformationBlockType1_NB_v1430',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType1_NB_v1430': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'cellSelectionInfo-v1430',
                {
                    'k': 'ref',
                    't': 'CellSelectionInfo_NB_v1430',
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SystemInformationBlockType1_NB_v1450',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType1_NB_v1450': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nrs-CRS-PowerOffset-v1450',
                {
                    'k': 'enum',
                    'names': [
                        'dB-6',
                        'dB-4dot77',
                        'dB-3',
                        'dB-1dot77',
                        'dB0',
                        'dB1',
                        'dB1dot23',
                        'dB2',
                        'dB3',
                        'dB4',
                        'dB4dot23',
                        'dB5',
                        'dB6',
                        'dB7',
                        'dB8',
                        'dB9',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SystemInformationBlockType1_NB_v1530',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType1_NB_v1530': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'tdd-Parameters-r15',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'tdd-Config-r15',
                            {
                                'k': 'ref',
                                't': 'TDD_Config_NB_r15',
                            },
                            False,
                            None,
                        ],
                        [
                            'tdd-SI-CarrierInfo-r15',
                            {
                                'k': 'enum',
                                'names': ['anchor', 'non-anchor'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'tdd-SI-SubframesBitmap-r15',
                            {
                                'k': 'ref',
                                't': 'DL_Bitmap_NB_r13',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'schedulingInfoList-v1530',
                {
                    'k': 'ref',
                    't': 'SchedulingInfoList_NB_v1530',
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SystemInformationBlockType1_NB_v1610',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType1_NB_v1610': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'cellAccessRelatedInfo-5GC-r16',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'plmn-IdentityList-r16',
                            {
                                'k': 'ref',
                                't': 'PLMN_IdentityList_5GC_NB_r16',
                            },
                            False,
                            None,
                        ],
                        [
                            'trackingAreaCode-5GC-r16',
                            {
                                'k': 'ref',
                                't': 'TrackingAreaCode_5GC_r15',
                            },
                            False,
                            None,
                        ],
                        [
                            'cellIdentity-r16',
                            {
                                'k': 'ref',
                                't': 'CellIdentity',
                            },
                            True,
                            None,
                        ],
                        [
                            'cellBarred-5GC-r16',
                            {
                                'k': 'enum',
                                'names': ['barred', 'notBarred'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SystemInformationBlockType1_NB_v1700',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType1_NB_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'cellAccessRelatedInfo-NTN-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'cellBarred-NTN-r17',
                            {
                                'k': 'enum',
                                'names': ['barred', 'notBarred'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'plmn-IdentityList-v1700',
                            {
                                'k': 'ref',
                                't': 'PLMN_IdentityList_NB_v1700',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType20_NB_r14': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'npdcch-SC-MCCH-Config-r14',
                {
                    'k': 'ref',
                    't': 'NPDCCH_SC_MCCH_Config_NB_r14',
                },
                False,
                None,
            ],
            [
                'sc-mcch-CarrierConfig-r14',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'dl-CarrierConfig-r14',
                            {
                                'k': 'ref',
                                't': 'DL_CarrierConfigCommon_NB_r14',
                            },
                        ],
                        [
                            'dl-CarrierIndex-r14',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 15,
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'sc-mcch-RepetitionPeriod-r14',
                {
                    'k': 'enum',
                    'names': [
                        'rf32',
                        'rf128',
                        'rf512',
                        'rf1024',
                        'rf2048',
                        'rf4096',
                        'rf8192',
                        'rf16384',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'sc-mcch-Offset-r14',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 10,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'sc-mcch-ModificationPeriod-r14',
                {
                    'k': 'enum',
                    'names': [
                        'rf32',
                        'rf128',
                        'rf256',
                        'rf512',
                        'rf1024',
                        'rf2048',
                        'rf4096',
                        'rf8192',
                        'rf16384',
                        'rf32768',
                        'rf65536',
                        'rf131072',
                        'rf262144',
                        'rf524288',
                        'rf1048576',
                        'spare1',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'sc-mcch-SchedulingInfo-r14',
                {
                    'k': 'ref',
                    't': 'SC_MCCH_SchedulingInfo_NB_r14',
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType22_NB_r14': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'dl-ConfigList-r14',
                {
                    'k': 'ref',
                    't': 'DL_ConfigCommonList_NB_r14',
                },
                True,
                None,
            ],
            [
                'ul-ConfigList-r14',
                {
                    'k': 'ref',
                    't': 'UL_ConfigCommonList_NB_r14',
                },
                True,
                None,
            ],
            [
                'pagingWeightAnchor-r14',
                {
                    'k': 'ref',
                    't': 'PagingWeight_NB_r14',
                },
                True,
                None,
            ],
            [
                'nprach-ProbabilityAnchorList-r14',
                {
                    'k': 'ref',
                    't': 'NPRACH_ProbabilityAnchorList_NB_r14',
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['mixedOperationModeConfig-r15', 'ul-ConfigList-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'mixedOperationModeConfig-r15',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'dl-ConfigListMixed-r15',
                                        {
                                            'k': 'ref',
                                            't': 'DL_ConfigCommonList_NB_r14',
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'ul-ConfigListMixed-r15',
                                        {
                                            'k': 'ref',
                                            't': 'UL_ConfigCommonList_NB_r14',
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'pagingDistribution-r15',
                                        {
                                            'k': 'enum',
                                            'names': ['true'],
                                            'ext': None,
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'nprach-Distribution-r15',
                                        {
                                            'k': 'enum',
                                            'names': ['true'],
                                            'ext': None,
                                        },
                                        True,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'ul-ConfigList-r15',
                            {
                                'k': 'ref',
                                't': 'UL_ConfigCommonListTDD_NB_r15',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['coverageBasedPagingConfig-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'coverageBasedPagingConfig-r17',
                            {
                                'k': 'ref',
                                't': 'CoverageBasedPagingConfig_NB_r17',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformationBlockType23_NB_r15': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'ul-ConfigList-v1530',
                {
                    'k': 'ref',
                    't': 'UL_ConfigCommonList_NB_v1530',
                },
                True,
                None,
            ],
            [
                'ul-ConfigListMixed-v1530',
                {
                    'k': 'ref',
                    't': 'UL_ConfigCommonList_NB_v1530',
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType27_NB_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'carrierFreqListEUTRA-r16',
                {
                    'k': 'ref',
                    't': 'CarrierFreqListEUTRA_NB_r16',
                },
                True,
                None,
            ],
            [
                'carrierFreqsListGERAN-r16',
                {
                    'k': 'ref',
                    't': 'CarrierFreqsListGERAN_NB_r16',
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType2_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'radioResourceConfigCommon-r13',
                {
                    'k': 'ref',
                    't': 'RadioResourceConfigCommonSIB_NB_r13',
                },
                False,
                None,
            ],
            [
                'ue-TimersAndConstants-r13',
                {
                    'k': 'ref',
                    't': 'UE_TimersAndConstants_NB_r13',
                },
                False,
                None,
            ],
            [
                'freqInfo-r13',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ul-CarrierFreq-r13',
                            {
                                'k': 'ref',
                                't': 'CarrierFreq_NB_r13',
                            },
                            True,
                            None,
                        ],
                        [
                            'additionalSpectrumEmission-r13',
                            {
                                'k': 'ref',
                                't': 'AdditionalSpectrumEmission',
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'timeAlignmentTimerCommon-r13',
                {
                    'k': 'ref',
                    't': 'TimeAlignmentTimer',
                },
                False,
                None,
            ],
            [
                'multiBandInfoList-r13',
                {
                    'k': 'seqof',
                    'size': [1, 8],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'AdditionalSpectrumEmission',
                    },
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['cp-Reestablishment-r14'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'cp-Reestablishment-r14',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['servingCellMeasInfo-r14', 'cqi-Reporting-r14'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'servingCellMeasInfo-r14',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'cqi-Reporting-r14',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['enhancedPHR-r15', 'freqInfo-v1530', 'cp-EDT-r15', 'up-EDT-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'enhancedPHR-r15',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'freqInfo-v1530',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'tdd-UL-DL-AlignmentOffset-r15',
                                        {
                                            'k': 'ref',
                                            't': 'TDD_UL_DL_AlignmentOffset_NB_r15',
                                        },
                                        False,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'cp-EDT-r15',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'up-EDT-r15',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': [
                    'earlySecurityReactivation-r16',
                    'cp-EDT-5GC-r16',
                    'up-EDT-5GC-r16',
                    'cp-PUR-EPC-r16',
                    'up-PUR-EPC-r16',
                    'cp-PUR-5GC-r16',
                    'up-PUR-5GC-r16',
                    'rai-ActivationEnh-r16',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'earlySecurityReactivation-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'cp-EDT-5GC-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'up-EDT-5GC-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'cp-PUR-EPC-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'up-PUR-EPC-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'cp-PUR-5GC-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'up-PUR-5GC-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'rai-ActivationEnh-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['gnss-PositionFixDurationReporting-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'gnss-PositionFixDurationReporting-r18',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformationBlockType31_NB_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'servingSatelliteInfo-r17',
                {
                    'k': 'ref',
                    't': 'ServingSatelliteInfo_r17',
                },
                False,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['servingSatelliteInfo-v1820'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'servingSatelliteInfo-v1820',
                            {
                                'k': 'ref',
                                't': 'ServingSatelliteInfo_v1820',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformationBlockType32_NB_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'satelliteInfoList-r17',
                {
                    'k': 'ref',
                    't': 'SatelliteInfoList_r17',
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['satelliteInfoList-v1800'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'satelliteInfoList-v1800',
                            {
                                'k': 'ref',
                                't': 'SatelliteInfoList_v1800',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['satelliteInfoList-v1830'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'satelliteInfoList-v1830',
                            {
                                'k': 'ref',
                                't': 'SatelliteInfoList_NB_v1830',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformationBlockType33_NB_r18': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'neighSatelliteInfoList-r18',
                {
                    'k': 'ref',
                    't': 'NeighSatelliteInfoList_r18',
                },
                True,
                None,
            ],
            [
                'neighValidityDuration-r18',
                {
                    'k': 'enum',
                    'names': [
                        's5',
                        's10',
                        's15',
                        's20',
                        's25',
                        's30',
                        's35',
                        's40',
                        's45',
                        's50',
                        's55',
                        's60',
                        's120',
                        's180',
                        's240',
                        's900',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformationBlockType3_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'cellReselectionInfoCommon-r13',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'q-Hyst-r13',
                            {
                                'k': 'enum',
                                'names': [
                                    'dB0',
                                    'dB1',
                                    'dB2',
                                    'dB3',
                                    'dB4',
                                    'dB5',
                                    'dB6',
                                    'dB8',
                                    'dB10',
                                    'dB12',
                                    'dB14',
                                    'dB16',
                                    'dB18',
                                    'dB20',
                                    'dB22',
                                    'dB24',
                                ],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'cellReselectionServingFreqInfo-r13',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            's-NonIntraSearch-r13',
                            {
                                'k': 'ref',
                                't': 'ReselectionThreshold',
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'intraFreqCellReselectionInfo-r13',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'q-RxLevMin-r13',
                            {
                                'k': 'ref',
                                't': 'Q_RxLevMin',
                            },
                            False,
                            None,
                        ],
                        [
                            'q-QualMin-r13',
                            {
                                'k': 'ref',
                                't': 'Q_QualMin_r9',
                            },
                            True,
                            None,
                        ],
                        [
                            'p-Max-r13',
                            {
                                'k': 'ref',
                                't': 'P_Max',
                            },
                            True,
                            None,
                        ],
                        [
                            's-IntraSearchP-r13',
                            {
                                'k': 'ref',
                                't': 'ReselectionThreshold',
                            },
                            False,
                            None,
                        ],
                        [
                            't-Reselection-r13',
                            {
                                'k': 'ref',
                                't': 'T_Reselection_NB_r13',
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'freqBandInfo-r13',
                {
                    'k': 'ref',
                    't': 'NS_PmaxList_NB_r13',
                },
                True,
                None,
            ],
            [
                'multiBandInfoList-r13',
                {
                    'k': 'seqof',
                    'size': [1, 8],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'NS_PmaxList_NB_r13',
                    },
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['intraFreqCellReselectionInfo-v1350'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'intraFreqCellReselectionInfo-v1350',
                            {
                                'k': 'ref',
                                't': 'IntraFreqCellReselectionInfo_NB_v1350',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['intraFreqCellReselectionInfo-v1360'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'intraFreqCellReselectionInfo-v1360',
                            {
                                'k': 'ref',
                                't': 'IntraFreqCellReselectionInfo_NB_v1360',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['intraFreqCellReselectionInfo-v1430'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'intraFreqCellReselectionInfo-v1430',
                            {
                                'k': 'ref',
                                't': 'IntraFreqCellReselectionInfo_NB_v1430',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['cellReselectionInfoCommon-v1450'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'cellReselectionInfoCommon-v1450',
                            {
                                'k': 'ref',
                                't': 'CellReselectionInfoCommon_NB_v1450',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['nsss-RRM-Config-r15', 'npbch-RRM-Config-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nsss-RRM-Config-r15',
                            {
                                'k': 'ref',
                                't': 'NSSS_RRM_Config_NB_r15',
                            },
                            True,
                            None,
                        ],
                        [
                            'npbch-RRM-Config-r15',
                            {
                                'k': 'enum',
                                'names': ['enabled'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['connMeasConfig-r17', 't-Service-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'connMeasConfig-r17',
                            {
                                'k': 'ref',
                                't': 'ConnMeasConfig_NB_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            't-Service-r17',
                            {
                                'k': 'ref',
                                't': 'TimeOffsetUTC_r17',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['satelliteAssistanceInfo-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'satelliteAssistanceInfo-r18',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'SatelliteId_r18',
                                },
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformationBlockType4_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'intraFreqNeighCellList-r13',
                {
                    'k': 'ref',
                    't': 'IntraFreqNeighCellList',
                },
                True,
                None,
            ],
            [
                'intraFreqExcludedCellList-r13',
                {
                    'k': 'ref',
                    't': 'IntraFreqExcludedCellList',
                },
                True,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['nsss-RRM-Config-r15', 'intraFreqNeighCellList-v1530'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nsss-RRM-Config-r15',
                            {
                                'k': 'ref',
                                't': 'NSSS_RRM_Config_NB_r15',
                            },
                            True,
                            None,
                        ],
                        [
                            'intraFreqNeighCellList-v1530',
                            {
                                'k': 'ref',
                                't': 'IntraFreqNeighCellList_NB_v1530',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformationBlockType5_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'interFreqCarrierFreqList-r13',
                {
                    'k': 'ref',
                    't': 'InterFreqCarrierFreqList_NB_r13',
                },
                False,
                None,
            ],
            [
                't-Reselection-r13',
                {
                    'k': 'ref',
                    't': 'T_Reselection_NB_r13',
                },
                False,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['scptm-FreqOffset-r14'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'scptm-FreqOffset-r14',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 8,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['interFreqCarrierFreqList-v1820'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'interFreqCarrierFreqList-v1820',
                            {
                                'k': 'ref',
                                't': 'InterFreqCarrierFreqList_NB_v1820',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SystemInformation_NB': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'criticalExtensions',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'systemInformation-r13',
                            {
                                'k': 'ref',
                                't': 'SystemInformation_NB_r13_IEs',
                            },
                        ],
                        [
                            'criticalExtensionsFuture',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [],
                                'extadd': [],
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SystemInformation_NB_r13_IEs': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'sib-TypeAndInfo-r13',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'choice',
                        'ext': True,
                        'alts': [
                            [
                                'sib2-r13',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType2_NB_r13',
                                },
                            ],
                            [
                                'sib3-r13',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType3_NB_r13',
                                },
                            ],
                            [
                                'sib4-r13',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType4_NB_r13',
                                },
                            ],
                            [
                                'sib5-r13',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType5_NB_r13',
                                },
                            ],
                            [
                                'sib14-r13',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType14_NB_r13',
                                },
                            ],
                            [
                                'sib16-r13',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType16_NB_r13',
                                },
                            ],
                        ],
                        'extadd': [
                            [
                                'sib15-v1430',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType15_NB_r14',
                                },
                            ],
                            [
                                'sib20-v1430',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType20_NB_r14',
                                },
                            ],
                            [
                                'sib22-v1430',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType22_NB_r14',
                                },
                            ],
                            [
                                'sib23-v1530',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType23_NB_r15',
                                },
                            ],
                            [
                                'sib27-v1610',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType27_NB_r16',
                                },
                            ],
                            [
                                'sib31-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType31_NB_r17',
                                },
                            ],
                            [
                                'sib32-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType32_NB_r17',
                                },
                            ],
                            [
                                'sib33-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SystemInformationBlockType33_NB_r18',
                                },
                            ],
                        ],
                    },
                },
                False,
                None,
            ],
            [
                'lateNonCriticalExtension',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'TDD_Config_NB_r15': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'subframeAssignment-r15',
                {
                    'k': 'enum',
                    'names': ['sa1', 'sa2', 'sa3', 'sa4', 'sa5'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'specialSubframePatterns-r15',
                {
                    'k': 'enum',
                    'names': [
                        'ssp0',
                        'ssp1',
                        'ssp2',
                        'ssp3',
                        'ssp4',
                        'ssp5',
                        'ssp6',
                        'ssp7',
                        'ssp8',
                        'ssp9',
                        'ssp10',
                        'ssp10-CRS-LessDwPTS',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'TDD_UL_DL_AlignmentOffset_NB_r15': {
        'k': 'enum',
        'names': ['khz-7dot5', 'khz0', 'khz7dot5'],
        'ext': None,
    },
    'TLE_EphemerisParameters_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'inclination-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 2097151,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'argumentPerigee-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 4194303,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'rightAscension-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 4194303,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'meanAnomaly-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 4194303,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'eccentricity-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 16777215,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'meanMotion-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 17179869183,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'bStarDecimal-r17',
                {
                    'k': 'int',
                    'lb': -99999,
                    'ub': 99999,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'bStarExponent-r17',
                {
                    'k': 'int',
                    'lb': -9,
                    'ub': 9,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'epochStar-r17',
                {
                    'k': 'int',
                    'lb': -1048575,
                    'ub': 1048575,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'T_Reselection_NB_r13': {
        'k': 'enum',
        'names': ['s0', 's3', 's6', 's9', 's12', 's15', 's18', 's21'],
        'ext': None,
    },
    'TimeAlignmentTimer': {
        'k': 'enum',
        'names': [
            'sf500',
            'sf750',
            'sf1280',
            'sf1920',
            'sf2560',
            'sf5120',
            'sf10240',
            'infinity',
        ],
        'ext': None,
    },
    'TimeOffsetUTC_r17': {
        'k': 'int',
        'lb': 0,
        'ub': 1048575,
        'ext': False,
    },
    'TimeReferenceInfo_r15': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'time-r15',
                {
                    'k': 'ref',
                    't': 'ReferenceTime_r15',
                },
                False,
                None,
            ],
            [
                'uncertainty-r15',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 12,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'timeInfoType-r15',
                {
                    'k': 'enum',
                    'names': ['localClock'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'referenceSFN-r15',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1023,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'TrackingAreaCode': {
        'k': 'bits',
        'size': [16, 16],
        'ext': False,
    },
    'TrackingAreaCode_5GC_r15': {
        'k': 'bits',
        'size': [24, 24],
        'ext': False,
    },
    'TrackingAreaList_NB_r17': {
        'k': 'seqof',
        'size': [1, 12],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'TrackingAreaCode',
        },
    },
    'UAC_AC1_SelectAssistInfo_r15': {
        'k': 'enum',
        'names': ['a', 'b', 'c'],
        'ext': None,
    },
    'UAC_BarringPerCatList_NB_r16': {
        'k': 'seqof',
        'size': [1, 63],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'UAC_BarringPerCat_NB_r16',
        },
    },
    'UAC_BarringPerCat_NB_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'uac-accessCategory-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'uac-BarringFactor-r16',
                {
                    'k': 'enum',
                    'names': [
                        'p00',
                        'p05',
                        'p10',
                        'p15',
                        'p20',
                        'p25',
                        'p30',
                        'p40',
                        'p50',
                        'p60',
                        'p70',
                        'p75',
                        'p80',
                        'p85',
                        'p90',
                        'p95',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'uac-BarringTime-r16',
                {
                    'k': 'enum',
                    'names': ['s4', 's8', 's16', 's32', 's64', 's128', 's256', 's512'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'UAC_Barring_NB_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'uac-BarringPerCatList-r16',
                {
                    'k': 'ref',
                    't': 'UAC_BarringPerCatList_NB_r16',
                },
                True,
                None,
            ],
            [
                'uac-AC1-SelectAssistInfo-r16',
                {
                    'k': 'ref',
                    't': 'UAC_AC1_SelectAssistInfo_r15',
                },
                True,
                None,
            ],
            [
                'uac-BarringForAccessIdentity-r16',
                {
                    'k': 'bits',
                    'size': [7, 7],
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'UAC_Param_NB_r16': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'uac-BarringCommon',
                {
                    'k': 'ref',
                    't': 'UAC_Barring_NB_r16',
                },
            ],
            [
                'uac-BarringPerPLMN-List',
                {
                    'k': 'seqof',
                    'size': [1, 6],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'UAC_Barring_NB_r16',
                    },
                },
            ],
        ],
        'extadd': [],
    },
    'UE_TimersAndConstants_NB_r13': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                't300-r13',
                {
                    'k': 'enum',
                    'names': [
                        'ms2500',
                        'ms4000',
                        'ms6000',
                        'ms10000',
                        'ms15000',
                        'ms25000',
                        'ms40000',
                        'ms60000',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't301-r13',
                {
                    'k': 'enum',
                    'names': [
                        'ms2500',
                        'ms4000',
                        'ms6000',
                        'ms10000',
                        'ms15000',
                        'ms25000',
                        'ms40000',
                        'ms60000',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't310-r13',
                {
                    'k': 'enum',
                    'names': ['ms0', 'ms200', 'ms500', 'ms1000', 'ms2000', 'ms4000', 'ms8000'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'n310-r13',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n3', 'n4', 'n6', 'n8', 'n10', 'n20'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't311-r13',
                {
                    'k': 'enum',
                    'names': [
                        'ms1000',
                        'ms3000',
                        'ms5000',
                        'ms10000',
                        'ms15000',
                        'ms20000',
                        'ms30000',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'n311-r13',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n3', 'n4', 'n5', 'n6', 'n8', 'n10'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['t311-v1350'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            't311-v1350',
                            {
                                'k': 'enum',
                                'names': ['ms40000', 'ms60000', 'ms90000', 'ms120000'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['t300-v1530', 't301-v1530', 't311-v1530', 't300-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            't300-v1530',
                            {
                                'k': 'enum',
                                'names': ['ms80000', 'ms100000', 'ms120000'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            't301-v1530',
                            {
                                'k': 'enum',
                                'names': ['ms80000', 'ms100000', 'ms120000'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            't311-v1530',
                            {
                                'k': 'enum',
                                'names': ['ms160000', 'ms200000'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            't300-r15',
                            {
                                'k': 'enum',
                                'names': [
                                    'ms6000',
                                    'ms10000',
                                    'ms15000',
                                    'ms25000',
                                    'ms40000',
                                    'ms60000',
                                    'ms80000',
                                    'ms120000',
                                ],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'UL_ConfigCommonListTDD_NB_r15': {
        'k': 'seqof',
        'size': [1, 15],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'UL_ConfigCommonTDD_NB_r15',
        },
    },
    'UL_ConfigCommonList_NB_r14': {
        'k': 'seqof',
        'size': [1, 15],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'UL_ConfigCommon_NB_r14',
        },
    },
    'UL_ConfigCommonList_NB_v1530': {
        'k': 'seqof',
        'size': [1, 15],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'UL_ConfigCommon_NB_v1530',
        },
    },
    'UL_ConfigCommonTDD_NB_r15': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'tdd-UL-DL-AlignmentOffset-r15',
                {
                    'k': 'ref',
                    't': 'TDD_UL_DL_AlignmentOffset_NB_r15',
                },
                False,
                None,
            ],
            [
                'nprach-ParametersListTDD-r15',
                {
                    'k': 'ref',
                    't': 'NPRACH_ParametersListTDD_NB_r15',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'UL_ConfigCommon_NB_r14': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'ul-CarrierFreq-r14',
                {
                    'k': 'ref',
                    't': 'CarrierFreq_NB_r13',
                },
                False,
                None,
            ],
            [
                'nprach-ParametersList-r14',
                {
                    'k': 'ref',
                    't': 'NPRACH_ParametersList_NB_r14',
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['nprach-ParametersListEDT-r15'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nprach-ParametersListEDT-r15',
                            {
                                'k': 'ref',
                                't': 'NPRACH_ParametersList_NB_r14',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['rsrp-ThresholdsPrachInfoList-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'rsrp-ThresholdsPrachInfoList-r16',
                            {
                                'k': 'ref',
                                't': 'RSRP_ThresholdsNPRACH_InfoList_NB_r13',
                            },
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'UL_ConfigCommon_NB_v1530': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'nprach-ParametersListFmt2-r15',
                {
                    'k': 'ref',
                    't': 'NPRACH_ParametersListFmt2_NB_r15',
                },
                True,
                None,
            ],
            [
                'nprach-ParametersListFmt2EDT-r15',
                {
                    'k': 'ref',
                    't': 'NPRACH_ParametersListFmt2_NB_r15',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'UL_ReferenceSignalsNPUSCH_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'groupHoppingEnabled-r13',
                {
                    'k': 'bool',
                },
                False,
                None,
            ],
            [
                'groupAssignmentNPUSCH-r13',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 29,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'UplinkPowerControlCommon_NB_r13': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'p0-NominalNPUSCH-r13',
                {
                    'k': 'int',
                    'lb': -126,
                    'ub': 24,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'alpha-r13',
                {
                    'k': 'enum',
                    'names': ['al0', 'al04', 'al05', 'al06', 'al07', 'al08', 'al09', 'al1'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'deltaPreambleMsg3-r13',
                {
                    'k': 'int',
                    'lb': -1,
                    'ub': 6,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'VelocityStateVector_r17': {
        'k': 'int',
        'lb': -131072,
        'ub': 131071,
        'ext': False,
    },
    'WUS_ConfigPerCarrier_NB_r15': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'maxDurationFactor-r15',
                {
                    'k': 'ref',
                    't': 'WUS_MaxDurationFactor_NB_r15',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'WUS_Config_NB_r15': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'maxDurationFactor-r15',
                {
                    'k': 'ref',
                    't': 'WUS_MaxDurationFactor_NB_r15',
                },
                False,
                None,
            ],
            [
                'numPOs-r15',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n4'],
                    'ext': None,
                },
                False,
                'n1',
            ],
            [
                'numDRX-CyclesRelaxed-r15',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n4', 'n8'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'timeOffsetDRX-r15',
                {
                    'k': 'enum',
                    'names': ['ms40', 'ms80', 'ms160', 'ms240'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'timeOffset-eDRX-Short-r15',
                {
                    'k': 'enum',
                    'names': ['ms40', 'ms80', 'ms160', 'ms240'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'timeOffset-eDRX-Long-r15',
                {
                    'k': 'enum',
                    'names': ['ms1000', 'ms2000'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'WUS_MaxDurationFactor_NB_r15': {
        'k': 'enum',
        'names': [
            'one128th',
            'one64th',
            'one32th',
            'one16th',
            'oneEighth',
            'oneQuarter',
            'oneHalf',
        ],
        'ext': None,
    },
}
