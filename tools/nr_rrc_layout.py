"""Generated unaligned-PER layout table for LTE RRC (TS 36.331).

Produced by tools/asn1gen.py -- DO NOT EDIT BY HAND.

Oracle:    pycrate 0.8.1
Generated: 2026-10-23 15:58:49

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
    'SIB19_r17',
    'SystemInformation',
    'BCCH_BCH_Message',
    'BCCH_DL_SCH_Message',
]

# The ASN.1 family the keys in TYPES belong to.  A verifier that is
# handed this table must select that family before it indexes pycrate,
# or it answers every key from whichever family it last selected.
FAMILY = 'nr'

# Reason strings for every construct the generator could not express.
# Keyed by the type that contains it; the engine raises PerError on them.
UNSUPPORTED = {
}

TYPES = {
    'ARFCN_ValueEUTRA': {
        'k': 'int',
        'lb': 0,
        'ub': 262143,
        'ext': False,
    },
    'ARFCN_ValueNR': {
        'k': 'int',
        'lb': 0,
        'ub': 3279165,
        'ext': False,
    },
    'ATG_Config_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'atg-gNB-Location-r18',
                {
                    'k': 'ref',
                    't': 'ReferenceLocation_r17',
                },
                True,
                None,
            ],
            [
                'height-gNB-r18',
                {
                    'k': 'int',
                    'lb': -16384,
                    'ub': 16383,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'cellSpecificKoffset-r18',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 3,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'ta-ReportATG-r18',
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
    'ATG_NeighCellConfigList_r18': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'ATG_NeighCellConfig_r18',
        },
    },
    'ATG_NeighCellConfig_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'atg-gNB-Location-r18',
                {
                    'k': 'ref',
                    't': 'ReferenceLocation_r17',
                },
                True,
                None,
            ],
            [
                'height-gNB-r18',
                {
                    'k': 'int',
                    'lb': -16384,
                    'ub': 16383,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'carrierFreq-r18',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueNR',
                },
                True,
                None,
            ],
            [
                'physCellId-r18',
                {
                    'k': 'ref',
                    't': 'PhysCellId',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'AdditionalPCIIndex_r17': {
        'k': 'int',
        'lb': 1,
        'ub': 7,
        'ext': False,
    },
    'AdditionalRACH_ConfigList_r17': {
        'k': 'seqof',
        'size': [1, 256],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'AdditionalRACH_Config_r17',
        },
    },
    'AdditionalRACH_Config_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'rach-ConfigCommon-r17',
                {
                    'k': 'ref',
                    't': 'RACH_ConfigCommon',
                },
                True,
                None,
            ],
            [
                'msgA-ConfigCommon-r17',
                {
                    'k': 'ref',
                    't': 'MsgA_ConfigCommon_r16',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'AdditionalSpectrumEmission': {
        'k': 'int',
        'lb': 0,
        'ub': 7,
        'ext': False,
    },
    'AdditionalSpectrumEmission_r18': {
        'k': 'int',
        'lb': 0,
        'ub': 39,
        'ext': False,
    },
    'AdditionalSpectrumEmission_v1760': {
        'k': 'int',
        'lb': 8,
        'ub': 39,
        'ext': False,
    },
    'ApplicableDisasterInfo_r17': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'noDisasterRoaming-r17',
                {
                    'k': 'null',
                },
            ],
            [
                'disasterRelatedIndication-r17',
                {
                    'k': 'null',
                },
            ],
            [
                'commonPLMNs-r17',
                {
                    'k': 'null',
                },
            ],
            [
                'dedicatedPLMNs-r17',
                {
                    'k': 'seqof',
                    'size': [1, 12],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PLMN_Identity',
                    },
                },
            ],
        ],
        'extadd': [],
    },
    'BCCH_BCH_Message': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'message',
                {
                    'k': 'ref',
                    't': 'BCCH_BCH_MessageType',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'BCCH_BCH_MessageType': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'mib',
                {
                    'k': 'ref',
                    't': 'MIB',
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
    'BCCH_Config': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'modificationPeriodCoeff',
                {
                    'k': 'enum',
                    'names': ['n2', 'n4', 'n8', 'n16'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'BCCH_DL_SCH_Message': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'message',
                {
                    'k': 'ref',
                    't': 'BCCH_DL_SCH_MessageType',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'BCCH_DL_SCH_MessageType': {
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
                            'systemInformation',
                            {
                                'k': 'ref',
                                't': 'SystemInformation',
                            },
                        ],
                        [
                            'systemInformationBlockType1',
                            {
                                'k': 'ref',
                                't': 'SIB1',
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
    'BWP': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'locationAndBandwidth',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 37949,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'subcarrierSpacing',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                False,
                None,
            ],
            [
                'cyclicPrefix',
                {
                    'k': 'enum',
                    'names': ['extended'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'BWP_DownlinkCommon': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'genericParameters',
                {
                    'k': 'ref',
                    't': 'BWP',
                },
                False,
                None,
            ],
            [
                'pdcch-ConfigCommon',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'release',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'setup',
                            {
                                'k': 'ref',
                                't': 'PDCCH_ConfigCommon',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'pdsch-ConfigCommon',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'release',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'setup',
                            {
                                'k': 'ref',
                                't': 'PDSCH_ConfigCommon',
                            },
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
    'BWP_UplinkCommon': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'genericParameters',
                {
                    'k': 'ref',
                    't': 'BWP',
                },
                False,
                None,
            ],
            [
                'rach-ConfigCommon',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'release',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'setup',
                            {
                                'k': 'ref',
                                't': 'RACH_ConfigCommon',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'pusch-ConfigCommon',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'release',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'setup',
                            {
                                'k': 'ref',
                                't': 'PUSCH_ConfigCommon',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'pucch-ConfigCommon',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'release',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'setup',
                            {
                                'k': 'ref',
                                't': 'PUCCH_ConfigCommon',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': [
                    'rach-ConfigCommonIAB-r16',
                    'useInterlacePUCCH-PUSCH-r16',
                    'msgA-ConfigCommon-r16',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'rach-ConfigCommonIAB-r16',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'release',
                                        {
                                            'k': 'null',
                                        },
                                    ],
                                    [
                                        'setup',
                                        {
                                            'k': 'ref',
                                            't': 'RACH_ConfigCommon',
                                        },
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'useInterlacePUCCH-PUSCH-r16',
                            {
                                'k': 'enum',
                                'names': ['enabled'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'msgA-ConfigCommon-r16',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'release',
                                        {
                                            'k': 'null',
                                        },
                                    ],
                                    [
                                        'setup',
                                        {
                                            'k': 'ref',
                                            't': 'MsgA_ConfigCommon_r16',
                                        },
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
            {
                'k': 'extgrp',
                'names': [
                    'enableRA-PrioritizationForSlicing-r17',
                    'additionalRACH-ConfigList-r17',
                    'rsrp-ThresholdMsg3-r17',
                    'numberOfMsg3-RepetitionsList-r17',
                    'mcs-Msg3-Repetitions-r17',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'enableRA-PrioritizationForSlicing-r17',
                            {
                                'k': 'bool',
                            },
                            True,
                            None,
                        ],
                        [
                            'additionalRACH-ConfigList-r17',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'release',
                                        {
                                            'k': 'null',
                                        },
                                    ],
                                    [
                                        'setup',
                                        {
                                            'k': 'ref',
                                            't': 'AdditionalRACH_ConfigList_r17',
                                        },
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'rsrp-ThresholdMsg3-r17',
                            {
                                'k': 'ref',
                                't': 'RSRP_Range',
                            },
                            True,
                            None,
                        ],
                        [
                            'numberOfMsg3-RepetitionsList-r17',
                            {
                                'k': 'seqof',
                                'size': [4, 4],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'NumberOfMsg3_Repetitions_r17',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'mcs-Msg3-Repetitions-r17',
                            {
                                'k': 'seqof',
                                'size': [8, 8],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 31,
                                    'ext': False,
                                },
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
                    'additionalRACH-perPCI-ToAddModList-r18',
                    'additionalRACH-perPCI-ToReleaseList-r18',
                    'rsrp-ThresholdMsg1-RepetitionNum2-r18',
                    'rsrp-ThresholdMsg1-RepetitionNum4-r18',
                    'rsrp-ThresholdMsg1-RepetitionNum8-r18',
                    'preambleTransMax-Msg1-Repetition-r18',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'additionalRACH-perPCI-ToAddModList-r18',
                            {
                                'k': 'seqof',
                                'size': [1, 7],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'RACH_ConfigTwoTA_r18',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'additionalRACH-perPCI-ToReleaseList-r18',
                            {
                                'k': 'seqof',
                                'size': [1, 7],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'AdditionalPCIIndex_r17',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'rsrp-ThresholdMsg1-RepetitionNum2-r18',
                            {
                                'k': 'ref',
                                't': 'RSRP_Range',
                            },
                            True,
                            None,
                        ],
                        [
                            'rsrp-ThresholdMsg1-RepetitionNum4-r18',
                            {
                                'k': 'ref',
                                't': 'RSRP_Range',
                            },
                            True,
                            None,
                        ],
                        [
                            'rsrp-ThresholdMsg1-RepetitionNum8-r18',
                            {
                                'k': 'ref',
                                't': 'RSRP_Range',
                            },
                            True,
                            None,
                        ],
                        [
                            'preambleTransMax-Msg1-Repetition-r18',
                            {
                                'k': 'enum',
                                'names': ['n1', 'n2', 'n4', 'n6', 'n8', 'n10', 'n20', 'n50', 'n100', 'n200'],
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
    'BeamMeasConfigIdle_NR_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'reportQuantityRS-Indexes-r16',
                {
                    'k': 'enum',
                    'names': ['rsrp', 'rsrq', 'both'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'maxNrofRS-IndexesToReport-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 32,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'includeBeamMeasurements-r16',
                {
                    'k': 'bool',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'CAG_IdentityInfo_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'cag-Identity-r16',
                {
                    'k': 'bits',
                    'size': [32, 32],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'manualCAGselectionAllowed-r16',
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
    'CFR_ConfigMCCH_MTCH_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'locationAndBandwidthBroadcast-r17',
                {
                    'k': 'ref',
                    't': 'LocationAndBandwidthBroadcast_r17',
                },
                True,
                None,
            ],
            [
                'pdsch-ConfigMCCH-r17',
                {
                    'k': 'ref',
                    't': 'PDSCH_ConfigBroadcast_r17',
                },
                True,
                None,
            ],
            [
                'commonControlResourceSetExt-r17',
                {
                    'k': 'ref',
                    't': 'ControlResourceSet',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqEUTRA': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'carrierFreq',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueEUTRA',
                },
                False,
                None,
            ],
            [
                'eutra-multiBandInfoList',
                {
                    'k': 'ref',
                    't': 'EUTRA_MultiBandInfoList',
                },
                True,
                None,
            ],
            [
                'eutra-FreqNeighCellList',
                {
                    'k': 'ref',
                    't': 'EUTRA_FreqNeighCellList',
                },
                True,
                None,
            ],
            [
                'eutra-ExcludedCellList',
                {
                    'k': 'ref',
                    't': 'EUTRA_FreqExcludedCellList',
                },
                True,
                None,
            ],
            [
                'allowedMeasBandwidth',
                {
                    'k': 'ref',
                    't': 'EUTRA_AllowedMeasBandwidth',
                },
                False,
                None,
            ],
            [
                'presenceAntennaPort1',
                {
                    'k': 'ref',
                    't': 'EUTRA_PresenceAntennaPort1',
                },
                False,
                None,
            ],
            [
                'cellReselectionPriority',
                {
                    'k': 'ref',
                    't': 'CellReselectionPriority',
                },
                True,
                None,
            ],
            [
                'cellReselectionSubPriority',
                {
                    'k': 'ref',
                    't': 'CellReselectionSubPriority',
                },
                True,
                None,
            ],
            [
                'threshX-High',
                {
                    'k': 'ref',
                    't': 'ReselectionThreshold',
                },
                False,
                None,
            ],
            [
                'threshX-Low',
                {
                    'k': 'ref',
                    't': 'ReselectionThreshold',
                },
                False,
                None,
            ],
            [
                'q-RxLevMin',
                {
                    'k': 'int',
                    'lb': -70,
                    'ub': -22,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'q-QualMin',
                {
                    'k': 'int',
                    'lb': -34,
                    'ub': -3,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'p-MaxEUTRA',
                {
                    'k': 'int',
                    'lb': -30,
                    'ub': 33,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'threshX-Q',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'threshX-HighQ',
                            {
                                'k': 'ref',
                                't': 'ReselectionThresholdQ',
                            },
                            False,
                            None,
                        ],
                        [
                            'threshX-LowQ',
                            {
                                'k': 'ref',
                                't': 'ReselectionThresholdQ',
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
    'CarrierFreqEUTRA_v1610': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'highSpeedEUTRACarrier-r16',
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
    'CarrierFreqEUTRA_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'eutra-FreqNeighHSDN-CellList-r17',
                {
                    'k': 'ref',
                    't': 'EUTRA_FreqNeighHSDN_CellList_r17',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqEUTRA_v1800': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'eutra-MultiBandInfoListAerial-r18',
                {
                    'k': 'ref',
                    't': 'EUTRA_MultiBandInfoListAerial_r18',
                },
                True,
                None,
            ],
            [
                'tn-AreaIdList-r18',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'TN_AreaId_r18',
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'CarrierFreqListEUTRA': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CarrierFreqEUTRA',
        },
    },
    'CarrierFreqListEUTRA_v1610': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CarrierFreqEUTRA_v1610',
        },
    },
    'CarrierFreqListEUTRA_v1700': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CarrierFreqEUTRA_v1700',
        },
    },
    'CarrierFreqListEUTRA_v1800': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CarrierFreqEUTRA_v1800',
        },
    },
    'CellAccessRelatedInfo': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'plmn-IdentityInfoList',
                {
                    'k': 'ref',
                    't': 'PLMN_IdentityInfoList',
                },
                False,
                None,
            ],
            [
                'cellReservedForOtherUse',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['cellReservedForFutureUse-r16', 'npn-IdentityInfoList-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'cellReservedForFutureUse-r16',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'npn-IdentityInfoList-r16',
                            {
                                'k': 'ref',
                                't': 'NPN_IdentityInfoList_r16',
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
                'names': ['snpn-AccessInfoList-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'snpn-AccessInfoList-r17',
                            {
                                'k': 'seqof',
                                'size': [1, 12],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'SNPN_AccessInfo_r17',
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
    'CellIdentity': {
        'k': 'bits',
        'size': [36, 36],
        'ext': False,
    },
    'CellListEUTRA_r16': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EUTRA_PhysCellIdRange',
        },
    },
    'CellListNR_r16': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PCI_Range',
        },
    },
    'CellReselectionPriority': {
        'k': 'int',
        'lb': 0,
        'ub': 7,
        'ext': False,
    },
    'CellReselectionSubPriority': {
        'k': 'enum',
        'names': ['oDot2', 'oDot4', 'oDot6', 'oDot8'],
        'ext': None,
    },
    'ConnEstFailureControl': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'connEstFailCount',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n3', 'n4'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'connEstFailOffsetValidity',
                {
                    'k': 'enum',
                    'names': ['s30', 's60', 's120', 's240', 's300', 's420', 's600', 's900'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'connEstFailOffset',
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
        'extadd': [],
    },
    'ControlResourceSet': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'controlResourceSetId',
                {
                    'k': 'ref',
                    't': 'ControlResourceSetId',
                },
                False,
                None,
            ],
            [
                'frequencyDomainResources',
                {
                    'k': 'bits',
                    'size': [45, 45],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'duration',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 3,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'cce-REG-MappingType',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'interleaved',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'reg-BundleSize',
                                        {
                                            'k': 'enum',
                                            'names': ['n2', 'n3', 'n6'],
                                            'ext': None,
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'interleaverSize',
                                        {
                                            'k': 'enum',
                                            'names': ['n2', 'n3', 'n6'],
                                            'ext': None,
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'shiftIndex',
                                        {
                                            'k': 'int',
                                            'lb': 0,
                                            'ub': 274,
                                            'ext': False,
                                        },
                                        True,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                        ],
                        [
                            'nonInterleaved',
                            {
                                'k': 'null',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'precoderGranularity',
                {
                    'k': 'enum',
                    'names': ['sameAsREG-bundle', 'allContiguousRBs'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'tci-StatesPDCCH-ToAddList',
                {
                    'k': 'seqof',
                    'size': [1, 64],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'TCI_StateId',
                    },
                },
                True,
                None,
            ],
            [
                'tci-StatesPDCCH-ToReleaseList',
                {
                    'k': 'seqof',
                    'size': [1, 64],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'TCI_StateId',
                    },
                },
                True,
                None,
            ],
            [
                'tci-PresentInDCI',
                {
                    'k': 'enum',
                    'names': ['enabled'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'pdcch-DMRS-ScramblingID',
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
        'extadd': [
            {
                'k': 'extgrp',
                'names': [
                    'rb-Offset-r16',
                    'tci-PresentDCI-1-2-r16',
                    'coresetPoolIndex-r16',
                    'controlResourceSetId-v1610',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'rb-Offset-r16',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 5,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'tci-PresentDCI-1-2-r16',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 3,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'coresetPoolIndex-r16',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'controlResourceSetId-v1610',
                            {
                                'k': 'ref',
                                't': 'ControlResourceSetId_v1610',
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
                'names': ['followUnifiedTCI-State-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'followUnifiedTCI-State-r17',
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
                'names': ['applyIndicatedTCI-State-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'applyIndicatedTCI-State-r18',
                            {
                                'k': 'enum',
                                'names': ['first', 'second', 'both', 'none'],
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
    'ControlResourceSetId': {
        'k': 'int',
        'lb': 0,
        'ub': 11,
        'ext': False,
    },
    'ControlResourceSetId_r16': {
        'k': 'int',
        'lb': 0,
        'ub': 15,
        'ext': False,
    },
    'ControlResourceSetId_v1610': {
        'k': 'int',
        'lb': 12,
        'ub': 15,
        'ext': False,
    },
    'ControlResourceSetZero': {
        'k': 'int',
        'lb': 0,
        'ub': 15,
        'ext': False,
    },
    'CoverageAreaInfoList_r18': {
        'k': 'seqof',
        'size': [1, 32],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'CoverageAreaInfo_r18',
        },
    },
    'CoverageAreaInfo_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'tn-AreaId-r18',
                {
                    'k': 'ref',
                    't': 'TN_AreaId_r18',
                },
                False,
                None,
            ],
            [
                'tn-ReferenceLocation-r18',
                {
                    'k': 'ref',
                    't': 'ReferenceLocation_r17',
                },
                False,
                None,
            ],
            [
                'tn-DistanceRadius-r18',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 65535,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'DownlinkConfigCommonSIB': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'frequencyInfoDL',
                {
                    'k': 'ref',
                    't': 'FrequencyInfoDL_SIB',
                },
                False,
                None,
            ],
            [
                'initialDownlinkBWP',
                {
                    'k': 'ref',
                    't': 'BWP_DownlinkCommon',
                },
                False,
                None,
            ],
            [
                'bcch-Config',
                {
                    'k': 'ref',
                    't': 'BCCH_Config',
                },
                False,
                None,
            ],
            [
                'pcch-Config',
                {
                    'k': 'ref',
                    't': 'PCCH_Config',
                },
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['pei-Config-r17', 'initialDownlinkBWP-RedCap-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'pei-Config-r17',
                            {
                                'k': 'ref',
                                't': 'PEI_Config_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'initialDownlinkBWP-RedCap-r17',
                            {
                                'k': 'ref',
                                't': 'BWP_DownlinkCommon',
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
                'names': ['frequencyInfoDL-v1800'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'frequencyInfoDL-v1800',
                            {
                                'k': 'ref',
                                't': 'FrequencyInfoDL_SIB_v1800',
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
    'DownlinkConfigCommonSIB_v1760': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'frequencyInfoDL-v1760',
                {
                    'k': 'ref',
                    't': 'FrequencyInfoDL_SIB_v1760',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'ERedCap_ConfigCommonSIB_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'cellBarred-eRedCap-r18',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'cellBarred-eRedCap1Rx-r18',
                            {
                                'k': 'enum',
                                'names': ['barred', 'notBarred'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'cellBarred-eRedCap2Rx-r18',
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
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'EUTRA_AllowedMeasBandwidth': {
        'k': 'enum',
        'names': ['mbw6', 'mbw15', 'mbw25', 'mbw50', 'mbw75', 'mbw100'],
        'ext': None,
    },
    'EUTRA_FreqExcludedCellList': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EUTRA_PhysCellIdRange',
        },
    },
    'EUTRA_FreqNeighCellInfo': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'physCellId',
                {
                    'k': 'ref',
                    't': 'EUTRA_PhysCellId',
                },
                False,
                None,
            ],
            [
                'dummy',
                {
                    'k': 'ref',
                    't': 'EUTRA_Q_OffsetRange',
                },
                False,
                None,
            ],
            [
                'q-RxLevMinOffsetCell',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 8,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'q-QualMinOffsetCell',
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
    'EUTRA_FreqNeighCellList': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EUTRA_FreqNeighCellInfo',
        },
    },
    'EUTRA_FreqNeighHSDN_CellList_r17': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EUTRA_PhysCellIdRange',
        },
    },
    'EUTRA_MBSFN_SubframeConfig': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'radioframeAllocationPeriod',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n4', 'n8', 'n16', 'n32'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'radioframeAllocationOffset',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 7,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'subframeAllocation1',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'oneFrame',
                            {
                                'k': 'bits',
                                'size': [6, 6],
                                'ext': False,
                            },
                        ],
                        [
                            'fourFrames',
                            {
                                'k': 'bits',
                                'size': [24, 24],
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
                'subframeAllocation2',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'oneFrame',
                            {
                                'k': 'bits',
                                'size': [2, 2],
                                'ext': False,
                            },
                        ],
                        [
                            'fourFrames',
                            {
                                'k': 'bits',
                                'size': [8, 8],
                                'ext': False,
                            },
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
    'EUTRA_MBSFN_SubframeConfigList': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EUTRA_MBSFN_SubframeConfig',
        },
    },
    'EUTRA_MultiBandInfo': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'eutra-FreqBandIndicator',
                {
                    'k': 'ref',
                    't': 'FreqBandIndicatorEUTRA',
                },
                False,
                None,
            ],
            [
                'eutra-NS-PmaxList',
                {
                    'k': 'ref',
                    't': 'EUTRA_NS_PmaxList',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'EUTRA_MultiBandInfoAerial_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'eutra-FreqBandIndicator-r18',
                {
                    'k': 'ref',
                    't': 'FreqBandIndicatorEUTRA',
                },
                False,
                None,
            ],
            [
                'eutra-NS-PmaxListAerial-r18',
                {
                    'k': 'ref',
                    't': 'EUTRA_NS_PmaxList',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'EUTRA_MultiBandInfoList': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EUTRA_MultiBandInfo',
        },
    },
    'EUTRA_MultiBandInfoListAerial_r18': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EUTRA_MultiBandInfoAerial_r18',
        },
    },
    'EUTRA_NS_PmaxList': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'EUTRA_NS_PmaxValue',
        },
    },
    'EUTRA_NS_PmaxValue': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'additionalPmax',
                {
                    'k': 'int',
                    'lb': -30,
                    'ub': 33,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'additionalSpectrumEmission',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 288,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'EUTRA_PhysCellId': {
        'k': 'int',
        'lb': 0,
        'ub': 503,
        'ext': False,
    },
    'EUTRA_PhysCellIdRange': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'start',
                {
                    'k': 'ref',
                    't': 'EUTRA_PhysCellId',
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
    'EUTRA_PresenceAntennaPort1': {
        'k': 'bool',
    },
    'EUTRA_Q_OffsetRange': {
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
    'EphemerisInfo_r17': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'positionVelocity-r17',
                {
                    'k': 'ref',
                    't': 'PositionVelocity_r17',
                },
            ],
            [
                'orbital-r17',
                {
                    'k': 'ref',
                    't': 'Orbital_r17',
                },
            ],
        ],
        'extadd': [],
    },
    'EpochTime_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'sfn-r17',
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
                'subFrameNR-r17',
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
    'FeatureCombinationPreambles_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'featureCombination-r17',
                {
                    'k': 'ref',
                    't': 'FeatureCombination_r17',
                },
                False,
                None,
            ],
            [
                'startPreambleForThisPartition-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'numberOfPreamblesPerSSB-ForThisPartition-r17',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 64,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'ssb-SharedRO-MaskIndex-r17',
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
                'groupBconfigured-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ra-SizeGroupA-r17',
                            {
                                'k': 'enum',
                                'names': [
                                    'b56',
                                    'b144',
                                    'b208',
                                    'b256',
                                    'b282',
                                    'b480',
                                    'b640',
                                    'b800',
                                    'b1000',
                                    'b72',
                                    'spare6',
                                    'spare5',
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
                            'messagePowerOffsetGroupB-r17',
                            {
                                'k': 'enum',
                                'names': ['minusinfinity', 'dB0', 'dB5', 'dB8', 'dB10', 'dB12', 'dB15', 'dB18'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'numberOfRA-PreamblesGroupA-r17',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 64,
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
                'separateMsgA-PUSCH-Config-r17',
                {
                    'k': 'ref',
                    't': 'MsgA_PUSCH_Config_r16',
                },
                True,
                None,
            ],
            [
                'msgA-RSRP-Threshold-r17',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'rsrp-ThresholdSSB-r17',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'deltaPreamble-r17',
                {
                    'k': 'int',
                    'lb': -1,
                    'ub': 6,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['msg1-RepetitionNum-r18', 'msg1-RepetitionTimeOffsetROGroup-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'msg1-RepetitionNum-r18',
                            {
                                'k': 'enum',
                                'names': ['n2', 'n4', 'n8', 'spare1'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'msg1-RepetitionTimeOffsetROGroup-r18',
                            {
                                'k': 'enum',
                                'names': ['n4', 'n8', 'n16', 'spare1'],
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
    'FeatureCombination_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'redCap-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'smallData-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'nsag-r17',
                {
                    'k': 'ref',
                    't': 'NSAG_List_r17',
                },
                True,
                None,
            ],
            [
                'msg3-Repetitions-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'msg1-Repetitions-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'eRedCap-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'spare2',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'spare1',
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
    'FeaturePriority_r17': {
        'k': 'int',
        'lb': 0,
        'ub': 7,
        'ext': False,
    },
    'FreqBandIndicatorEUTRA': {
        'k': 'int',
        'lb': 1,
        'ub': 256,
        'ext': False,
    },
    'FreqBandIndicatorNR': {
        'k': 'int',
        'lb': 1,
        'ub': 1024,
        'ext': False,
    },
    'FreqPriorityListSlicing_r17': {
        'k': 'seqof',
        'size': [1, 9],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'FreqPrioritySlicing_r17',
        },
    },
    'FreqPrioritySlicing_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'dl-ImplicitCarrierFreq-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 8,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'sliceInfoList-r17',
                {
                    'k': 'ref',
                    't': 'SliceInfoList_r17',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'FrequencyInfoDL_SIB': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'frequencyBandList',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB',
                },
                False,
                None,
            ],
            [
                'offsetToPointA',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 2199,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'scs-SpecificCarrierList',
                {
                    'k': 'seqof',
                    'size': [1, 5],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SCS_SpecificCarrier',
                    },
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'FrequencyInfoDL_SIB_v1760': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'frequencyBandList-v1760',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB_v1760',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'FrequencyInfoDL_SIB_v1800': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'frequencyBandListAerial-r18',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_Aerial_SIB_r18',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'FrequencyInfoUL_SIB': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'frequencyBandList',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB',
                },
                True,
                None,
            ],
            [
                'absoluteFrequencyPointA',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueNR',
                },
                True,
                None,
            ],
            [
                'scs-SpecificCarrierList',
                {
                    'k': 'seqof',
                    'size': [1, 5],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SCS_SpecificCarrier',
                    },
                },
                False,
                None,
            ],
            [
                'p-Max',
                {
                    'k': 'ref',
                    't': 'P_Max',
                },
                True,
                None,
            ],
            [
                'frequencyShift7p5khz',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['frequencyBandListAerial-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'frequencyBandListAerial-r18',
                            {
                                'k': 'ref',
                                't': 'MultiFrequencyBandListNR_Aerial_SIB_r18',
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
    'FrequencyInfoUL_SIB_v1760': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'frequencyBandList-v1760',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB_v1760',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'GIN_Element_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'plmn-Identity-r17',
                {
                    'k': 'ref',
                    't': 'PLMN_Identity',
                },
                False,
                None,
            ],
            [
                'nid-List-r17',
                {
                    'k': 'seqof',
                    'size': [1, 24],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'NID_r16',
                    },
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'GINs_PerSNPN_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'supportedGINs-r17',
                {
                    'k': 'bits',
                    'size': [1, 24],
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'GNSS_ID_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'gnss-id-r16',
                {
                    'k': 'enum',
                    'names': ['gps', 'sbas', 'qzss', 'galileo', 'glonass', 'bds'],
                    'ext': ['navic-v1760'],
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'GroupB_ConfiguredTwoStepRA_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ra-MsgA-SizeGroupA-r16',
                {
                    'k': 'enum',
                    'names': [
                        'b56',
                        'b144',
                        'b208',
                        'b256',
                        'b282',
                        'b480',
                        'b640',
                        'b800',
                        'b1000',
                        'b72',
                        'spare6',
                        'spare5',
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
                'messagePowerOffsetGroupB-r16',
                {
                    'k': 'enum',
                    'names': ['minusinfinity', 'dB0', 'dB5', 'dB8', 'dB10', 'dB12', 'dB15', 'dB18'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'numberOfRA-PreamblesGroupA-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 64,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'HRNN_List_r16': {
        'k': 'seqof',
        'size': [1, 12],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'HRNN_r16',
        },
    },
    'HRNN_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'hrnn-r16',
                {
                    'k': 'octets',
                    'size': [1, 48],
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'HighSpeedConfigFR2_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'highSpeedMeasFlagFR2-r17',
                {
                    'k': 'enum',
                    'names': ['set1', 'set2'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'highSpeedDeploymentTypeFR2-r17',
                {
                    'k': 'enum',
                    'names': ['unidirectional', 'bidirectional'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'highSpeedLargeOneStepUL-TimingFR2-r17',
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
    'HighSpeedConfig_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'highSpeedMeasFlag-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'highSpeedDemodFlag-r16',
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
    'InterFreqAllowedCellList_r16': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PCI_Range',
        },
    },
    'InterFreqCAG_CellListPerPLMN_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'plmn-IdentityIndex-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 12,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'cag-CellList-r16',
                {
                    'k': 'seqof',
                    'size': [1, 16],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PCI_Range',
                    },
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqCarrierFreqInfo': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'dl-CarrierFreq',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueNR',
                },
                False,
                None,
            ],
            [
                'frequencyBandList',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB',
                },
                True,
                None,
            ],
            [
                'frequencyBandListSUL',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB',
                },
                True,
                None,
            ],
            [
                'nrofSS-BlocksToAverage',
                {
                    'k': 'int',
                    'lb': 2,
                    'ub': 16,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'absThreshSS-BlocksConsolidation',
                {
                    'k': 'ref',
                    't': 'ThresholdNR',
                },
                True,
                None,
            ],
            [
                'smtc',
                {
                    'k': 'ref',
                    't': 'SSB_MTC',
                },
                True,
                None,
            ],
            [
                'ssbSubcarrierSpacing',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                False,
                None,
            ],
            [
                'ssb-ToMeasure',
                {
                    'k': 'ref',
                    't': 'SSB_ToMeasure',
                },
                True,
                None,
            ],
            [
                'deriveSSB-IndexFromCell',
                {
                    'k': 'bool',
                },
                False,
                None,
            ],
            [
                'ss-RSSI-Measurement',
                {
                    'k': 'ref',
                    't': 'SS_RSSI_Measurement',
                },
                True,
                None,
            ],
            [
                'q-RxLevMin',
                {
                    'k': 'ref',
                    't': 'Q_RxLevMin',
                },
                False,
                None,
            ],
            [
                'q-RxLevMinSUL',
                {
                    'k': 'ref',
                    't': 'Q_RxLevMin',
                },
                True,
                None,
            ],
            [
                'q-QualMin',
                {
                    'k': 'ref',
                    't': 'Q_QualMin',
                },
                True,
                None,
            ],
            [
                'p-Max',
                {
                    'k': 'ref',
                    't': 'P_Max',
                },
                True,
                None,
            ],
            [
                't-ReselectionNR',
                {
                    'k': 'ref',
                    't': 'T_Reselection',
                },
                False,
                None,
            ],
            [
                't-ReselectionNR-SF',
                {
                    'k': 'ref',
                    't': 'SpeedStateScaleFactors',
                },
                True,
                None,
            ],
            [
                'threshX-HighP',
                {
                    'k': 'ref',
                    't': 'ReselectionThreshold',
                },
                False,
                None,
            ],
            [
                'threshX-LowP',
                {
                    'k': 'ref',
                    't': 'ReselectionThreshold',
                },
                False,
                None,
            ],
            [
                'threshX-Q',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'threshX-HighQ',
                            {
                                'k': 'ref',
                                't': 'ReselectionThresholdQ',
                            },
                            False,
                            None,
                        ],
                        [
                            'threshX-LowQ',
                            {
                                'k': 'ref',
                                't': 'ReselectionThresholdQ',
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
                'cellReselectionPriority',
                {
                    'k': 'ref',
                    't': 'CellReselectionPriority',
                },
                True,
                None,
            ],
            [
                'cellReselectionSubPriority',
                {
                    'k': 'ref',
                    't': 'CellReselectionSubPriority',
                },
                True,
                None,
            ],
            [
                'q-OffsetFreq',
                {
                    'k': 'ref',
                    't': 'Q_OffsetRange',
                },
                False,
                'dB0',
            ],
            [
                'interFreqNeighCellList',
                {
                    'k': 'ref',
                    't': 'InterFreqNeighCellList',
                },
                True,
                None,
            ],
            [
                'interFreqExcludedCellList',
                {
                    'k': 'ref',
                    't': 'InterFreqExcludedCellList',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqCarrierFreqInfo_v1610': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'interFreqNeighCellList-v1610',
                {
                    'k': 'ref',
                    't': 'InterFreqNeighCellList_v1610',
                },
                True,
                None,
            ],
            [
                'smtc2-LP-r16',
                {
                    'k': 'ref',
                    't': 'SSB_MTC2_LP_r16',
                },
                True,
                None,
            ],
            [
                'interFreqAllowedCellList-r16',
                {
                    'k': 'ref',
                    't': 'InterFreqAllowedCellList_r16',
                },
                True,
                None,
            ],
            [
                'ssb-PositionQCL-Common-r16',
                {
                    'k': 'ref',
                    't': 'SSB_PositionQCL_Relation_r16',
                },
                True,
                None,
            ],
            [
                'interFreqCAG-CellList-r16',
                {
                    'k': 'seqof',
                    'size': [1, 12],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'InterFreqCAG_CellListPerPLMN_r16',
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqCarrierFreqInfo_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'interFreqNeighHSDN-CellList-r17',
                {
                    'k': 'ref',
                    't': 'InterFreqNeighHSDN_CellList_r17',
                },
                True,
                None,
            ],
            [
                'highSpeedMeasInterFreq-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'redCapAccessAllowed-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ssb-PositionQCL-Common-r17',
                {
                    'k': 'ref',
                    't': 'SSB_PositionQCL_Relation_r17',
                },
                True,
                None,
            ],
            [
                'interFreqNeighCellList-v1710',
                {
                    'k': 'ref',
                    't': 'InterFreqNeighCellList_v1710',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqCarrierFreqInfo_v1720': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'smtc4list-r17',
                {
                    'k': 'ref',
                    't': 'SSB_MTC4List_r17',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqCarrierFreqInfo_v1730': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'channelAccessMode2-r17',
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
    'InterFreqCarrierFreqInfo_v1760': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'frequencyBandList-v1760',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB_v1760',
                },
                True,
                None,
            ],
            [
                'frequencyBandListSUL-v1760',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB_v1760',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqCarrierFreqInfo_v1800': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'dl-CarrierFreq-r18',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueNR',
                },
                True,
                None,
            ],
            [
                'frequencyBandList-r18',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_SIB',
                },
                True,
                None,
            ],
            [
                'frequencyBandListAerial-r18',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR_Aerial_SIB_r18',
                },
                True,
                None,
            ],
            [
                'mobileIAB-CellList-r18',
                {
                    'k': 'ref',
                    't': 'PCI_Range',
                },
                True,
                None,
            ],
            [
                'mobileIAB-Freq-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'eRedCapAccessAllowed-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'tn-AreaIdList-r18',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'TN_AreaId_r18',
                    },
                },
                True,
                None,
            ],
            [
                'accessAllowed2RxXR-r18',
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
    'InterFreqCarrierFreqList': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo',
        },
    },
    'InterFreqCarrierFreqList_v1610': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo_v1610',
        },
    },
    'InterFreqCarrierFreqList_v1700': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo_v1700',
        },
    },
    'InterFreqCarrierFreqList_v1720': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo_v1720',
        },
    },
    'InterFreqCarrierFreqList_v1730': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo_v1730',
        },
    },
    'InterFreqCarrierFreqList_v1760': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo_v1760',
        },
    },
    'InterFreqCarrierFreqList_v1800': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqCarrierFreqInfo_v1800',
        },
    },
    'InterFreqExcludedCellList': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PCI_Range',
        },
    },
    'InterFreqNeighCellInfo': {
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
            [
                'q-RxLevMinOffsetCell',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 8,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'q-RxLevMinOffsetCellSUL',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 8,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'q-QualMinOffsetCell',
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
    'InterFreqNeighCellInfo_v1610': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ssb-PositionQCL-r16',
                {
                    'k': 'ref',
                    't': 'SSB_PositionQCL_Relation_r16',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqNeighCellInfo_v1710': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ssb-PositionQCL-r17',
                {
                    'k': 'ref',
                    't': 'SSB_PositionQCL_Relation_r17',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InterFreqNeighCellList': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqNeighCellInfo',
        },
    },
    'InterFreqNeighCellList_v1610': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqNeighCellInfo_v1610',
        },
    },
    'InterFreqNeighCellList_v1710': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'InterFreqNeighCellInfo_v1710',
        },
    },
    'InterFreqNeighHSDN_CellList_r17': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PCI_Range',
        },
    },
    'IntraFreqAllowedCellList_r16': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PCI_Range',
        },
    },
    'IntraFreqCAG_CellListPerPLMN_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'plmn-IdentityIndex-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 12,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'cag-CellList-r16',
                {
                    'k': 'seqof',
                    'size': [1, 16],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PCI_Range',
                    },
                },
                False,
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
            't': 'PCI_Range',
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
            [
                'q-RxLevMinOffsetCell',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 8,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'q-RxLevMinOffsetCellSUL',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 8,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'q-QualMinOffsetCell',
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
    'IntraFreqNeighCellInfo_v1610': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ssb-PositionQCL-r16',
                {
                    'k': 'ref',
                    't': 'SSB_PositionQCL_Relation_r16',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'IntraFreqNeighCellInfo_v1710': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ssb-PositionQCL-r17',
                {
                    'k': 'ref',
                    't': 'SSB_PositionQCL_Relation_r17',
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
    'IntraFreqNeighCellList_v1610': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'IntraFreqNeighCellInfo_v1610',
        },
    },
    'IntraFreqNeighCellList_v1710': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'IntraFreqNeighCellInfo_v1710',
        },
    },
    'IntraFreqNeighHSDN_CellList_r17': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PCI_Range',
        },
    },
    'LocationAndBandwidthBroadcast_r17': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'sameAsSib1ConfiguredLocationAndBW',
                {
                    'k': 'null',
                },
            ],
            [
                'locationAndBandwidth',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 37949,
                    'ext': False,
                },
            ],
        ],
        'extadd': [],
    },
    'MBS_FSAI_InterFreqList_r17': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'MBS_FSAI_InterFreq_r17',
        },
    },
    'MBS_FSAI_InterFreq_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'dl-CarrierFreq-r17',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueNR',
                },
                False,
                None,
            ],
            [
                'mbs-FSAI-List-r17',
                {
                    'k': 'ref',
                    't': 'MBS_FSAI_List_r17',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'MBS_FSAI_List_r17': {
        'k': 'seqof',
        'size': [1, 64],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'MBS_FSAI_r17',
        },
    },
    'MBS_FSAI_r17': {
        'k': 'octets',
        'size': [3, 3],
        'ext': False,
        'containing': None,
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
    'MCCH_Config_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'mcch-RepetitionPeriodAndOffset-r17',
                {
                    'k': 'ref',
                    't': 'MCCH_RepetitionPeriodAndOffset_r17',
                },
                False,
                None,
            ],
            [
                'mcch-WindowStartSlot-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 79,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'mcch-WindowDuration-r17',
                {
                    'k': 'enum',
                    'names': ['sl2', 'sl4', 'sl8', 'sl10', 'sl20', 'sl40', 'sl80', 'sl160'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'mcch-ModificationPeriod-r17',
                {
                    'k': 'enum',
                    'names': [
                        'rf2',
                        'rf4',
                        'rf8',
                        'rf16',
                        'rf32',
                        'rf64',
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
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'MCCH_RepetitionPeriodAndOffset_r17': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'rf1-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 0,
                    'ext': False,
                },
            ],
            [
                'rf2-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1,
                    'ext': False,
                },
            ],
            [
                'rf4-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 3,
                    'ext': False,
                },
            ],
            [
                'rf8-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 7,
                    'ext': False,
                },
            ],
            [
                'rf16-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 15,
                    'ext': False,
                },
            ],
            [
                'rf32-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 31,
                    'ext': False,
                },
            ],
            [
                'rf64-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
            ],
            [
                'rf128-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 127,
                    'ext': False,
                },
            ],
            [
                'rf256-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 255,
                    'ext': False,
                },
            ],
        ],
        'extadd': [],
    },
    'MCC_MNC_Digit': {
        'k': 'int',
        'lb': 0,
        'ub': 9,
        'ext': False,
    },
    'MIB': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'systemFrameNumber',
                {
                    'k': 'bits',
                    'size': [6, 6],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'subCarrierSpacingCommon',
                {
                    'k': 'enum',
                    'names': ['scs15or60', 'scs30or120'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'ssb-SubcarrierOffset',
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
                'dmrs-TypeA-Position',
                {
                    'k': 'enum',
                    'names': ['pos2', 'pos3'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'pdcch-ConfigSIB1',
                {
                    'k': 'ref',
                    't': 'PDCCH_ConfigSIB1',
                },
                False,
                None,
            ],
            [
                'cellBarred',
                {
                    'k': 'enum',
                    'names': ['barred', 'notBarred'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'intraFreqReselection',
                {
                    'k': 'enum',
                    'names': ['allowed', 'notAllowed'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'spare',
                {
                    'k': 'bits',
                    'size': [1, 1],
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
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
    'MT_SDT_ConfigCommonSIB_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'mt-SDT-RSRP-Threshold-r18',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'sdt-LogicalChannelSR-DelayTimer-r18',
                {
                    'k': 'enum',
                    'names': [
                        'sf20',
                        'sf40',
                        'sf64',
                        'sf128',
                        'sf512',
                        'sf1024',
                        'sf2560',
                        'spare1',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                't319a-r18',
                {
                    'k': 'enum',
                    'names': [
                        'ms100',
                        'ms200',
                        'ms300',
                        'ms400',
                        'ms600',
                        'ms1000',
                        'ms2000',
                        'ms3000',
                        'ms4000',
                        'spare7',
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
        ],
        'extadd': [],
    },
    'MeasIdleCarrierEUTRA_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'carrierFreqEUTRA-r16',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueEUTRA',
                },
                False,
                None,
            ],
            [
                'allowedMeasBandwidth-r16',
                {
                    'k': 'ref',
                    't': 'EUTRA_AllowedMeasBandwidth',
                },
                False,
                None,
            ],
            [
                'measCellListEUTRA-r16',
                {
                    'k': 'ref',
                    't': 'CellListEUTRA_r16',
                },
                True,
                None,
            ],
            [
                'reportQuantitiesEUTRA-r16',
                {
                    'k': 'enum',
                    'names': ['rsrp', 'rsrq', 'both'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'qualityThresholdEUTRA-r16',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'idleRSRP-Threshold-EUTRA-r16',
                            {
                                'k': 'ref',
                                't': 'RSRP_RangeEUTRA',
                            },
                            True,
                            None,
                        ],
                        [
                            'idleRSRQ-Threshold-EUTRA-r16',
                            {
                                'k': 'ref',
                                't': 'RSRQ_RangeEUTRA_r16',
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
    'MeasIdleCarrierNR_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'carrierFreq-r16',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueNR',
                },
                False,
                None,
            ],
            [
                'ssbSubcarrierSpacing-r16',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                False,
                None,
            ],
            [
                'frequencyBandList',
                {
                    'k': 'ref',
                    't': 'MultiFrequencyBandListNR',
                },
                True,
                None,
            ],
            [
                'measCellListNR-r16',
                {
                    'k': 'ref',
                    't': 'CellListNR_r16',
                },
                True,
                None,
            ],
            [
                'reportQuantities-r16',
                {
                    'k': 'enum',
                    'names': ['rsrp', 'rsrq', 'both'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'qualityThreshold-r16',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'idleRSRP-Threshold-NR-r16',
                            {
                                'k': 'ref',
                                't': 'RSRP_Range',
                            },
                            True,
                            None,
                        ],
                        [
                            'idleRSRQ-Threshold-NR-r16',
                            {
                                'k': 'ref',
                                't': 'RSRQ_Range',
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
                'ssb-MeasConfig-r16',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nrofSS-BlocksToAverage-r16',
                            {
                                'k': 'int',
                                'lb': 2,
                                'ub': 16,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'absThreshSS-BlocksConsolidation-r16',
                            {
                                'k': 'ref',
                                't': 'ThresholdNR',
                            },
                            True,
                            None,
                        ],
                        [
                            'smtc-r16',
                            {
                                'k': 'ref',
                                't': 'SSB_MTC',
                            },
                            True,
                            None,
                        ],
                        [
                            'ssb-ToMeasure-r16',
                            {
                                'k': 'ref',
                                't': 'SSB_ToMeasure',
                            },
                            True,
                            None,
                        ],
                        [
                            'deriveSSB-IndexFromCell-r16',
                            {
                                'k': 'bool',
                            },
                            False,
                            None,
                        ],
                        [
                            'ss-RSSI-Measurement-r16',
                            {
                                'k': 'ref',
                                't': 'SS_RSSI_Measurement',
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
                'beamMeasConfigIdle-r16',
                {
                    'k': 'ref',
                    't': 'BeamMeasConfigIdle_NR_r16',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'MeasIdleConfigSIB_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'measIdleCarrierListNR-r16',
                {
                    'k': 'seqof',
                    'size': [1, 8],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'MeasIdleCarrierNR_r16',
                    },
                },
                True,
                None,
            ],
            [
                'measIdleCarrierListEUTRA-r16',
                {
                    'k': 'seqof',
                    'size': [1, 8],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'MeasIdleCarrierEUTRA_r16',
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': [
                    'measIdleCarrierListNR-LessThan5MHz-r18',
                    'measReselectionCarrierListNR-r18',
                    'measReselectionCarrierListNR-LessThan5MHz-r18',
                    'measIdleValidityDuration-r18',
                    'measReselectionValidityDuration-r18',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'measIdleCarrierListNR-LessThan5MHz-r18',
                            {
                                'k': 'seqof',
                                'size': [1, 8],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'MeasIdleCarrierNR_r16',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'measReselectionCarrierListNR-r18',
                            {
                                'k': 'seqof',
                                'size': [1, 8],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'MeasReselectionCarrierNR_r18',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'measReselectionCarrierListNR-LessThan5MHz-r18',
                            {
                                'k': 'seqof',
                                'size': [1, 8],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'MeasReselectionCarrierNR_r18',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'measIdleValidityDuration-r18',
                            {
                                'k': 'ref',
                                't': 'MeasurementValidityDuration_r18',
                            },
                            True,
                            None,
                        ],
                        [
                            'measReselectionValidityDuration-r18',
                            {
                                'k': 'ref',
                                't': 'MeasurementValidityDuration_r18',
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
    'MeasReselectionCarrierNR_r18': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'carrierFreq-r18',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueNR',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'MeasurementValidityDuration_r18': {
        'k': 'enum',
        'names': ['s5', 's10', 's20', 's50', 's100', 'spare3', 'spare2', 'spare1'],
        'ext': None,
    },
    'MobilityStateParameters': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                't-Evaluation',
                {
                    'k': 'enum',
                    'names': ['s30', 's60', 's120', 's180', 's240', 'spare3', 'spare2', 'spare1'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't-HystNormal',
                {
                    'k': 'enum',
                    'names': ['s30', 's60', 's120', 's180', 's240', 'spare3', 'spare2', 'spare1'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'n-CellChangeMedium',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 16,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'n-CellChangeHigh',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 16,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'MsgA_ConfigCommon_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'rach-ConfigCommonTwoStepRA-r16',
                {
                    'k': 'ref',
                    't': 'RACH_ConfigCommonTwoStepRA_r16',
                },
                False,
                None,
            ],
            [
                'msgA-PUSCH-Config-r16',
                {
                    'k': 'ref',
                    't': 'MsgA_PUSCH_Config_r16',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'MsgA_DMRS_Config_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'msgA-DMRS-AdditionalPosition-r16',
                {
                    'k': 'enum',
                    'names': ['pos0', 'pos1', 'pos3'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'msgA-MaxLength-r16',
                {
                    'k': 'enum',
                    'names': ['len2'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'msgA-PUSCH-DMRS-CDM-Group-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-PUSCH-NrofPorts-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-ScramblingID0-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 65535,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-ScramblingID1-r16',
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
    'MsgA_PUSCH_Config_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'msgA-PUSCH-ResourceGroupA-r16',
                {
                    'k': 'ref',
                    't': 'MsgA_PUSCH_Resource_r16',
                },
                True,
                None,
            ],
            [
                'msgA-PUSCH-ResourceGroupB-r16',
                {
                    'k': 'ref',
                    't': 'MsgA_PUSCH_Resource_r16',
                },
                True,
                None,
            ],
            [
                'msgA-TransformPrecoder-r16',
                {
                    'k': 'enum',
                    'names': ['enabled', 'disabled'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'msgA-DataScramblingIndex-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1023,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-DeltaPreamble-r16',
                {
                    'k': 'int',
                    'lb': -1,
                    'ub': 6,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'MsgA_PUSCH_Resource_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'msgA-MCS-r16',
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
                'nrofSlotsMsgA-PUSCH-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 4,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'nrofMsgA-PO-PerSlot-r16',
                {
                    'k': 'enum',
                    'names': ['one', 'two', 'three', 'six'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'msgA-PUSCH-TimeDomainOffset-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 32,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'msgA-PUSCH-TimeDomainAllocation-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 16,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'startSymbolAndLengthMsgA-PO-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 127,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'mappingTypeMsgA-PUSCH-r16',
                {
                    'k': 'enum',
                    'names': ['typeA', 'typeB'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'guardPeriodMsgA-PUSCH-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 3,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'guardBandMsgA-PUSCH-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'frequencyStartMsgA-PUSCH-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 274,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'nrofPRBs-PerMsgA-PO-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 32,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'nrofMsgA-PO-FDM-r16',
                {
                    'k': 'enum',
                    'names': ['one', 'two', 'four', 'eight'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'msgA-IntraSlotFrequencyHopping-r16',
                {
                    'k': 'enum',
                    'names': ['enabled'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'msgA-HoppingBits-r16',
                {
                    'k': 'bits',
                    'size': [2, 2],
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-DMRS-Config-r16',
                {
                    'k': 'ref',
                    't': 'MsgA_DMRS_Config_r16',
                },
                False,
                None,
            ],
            [
                'nrofDMRS-Sequences-r16',
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
                'msgA-Alpha-r16',
                {
                    'k': 'enum',
                    'names': [
                        'alpha0',
                        'alpha04',
                        'alpha05',
                        'alpha06',
                        'alpha07',
                        'alpha08',
                        'alpha09',
                        'alpha1',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'interlaceIndexFirstPO-MsgA-PUSCH-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 10,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'nrofInterlacesPerMsgA-PO-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 10,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'MultiFrequencyBandListNR': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'FreqBandIndicatorNR',
        },
    },
    'MultiFrequencyBandListNR_Aerial_SIB_r18': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NR_MultiBandInfoAerial_r18',
        },
    },
    'MultiFrequencyBandListNR_SIB': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NR_MultiBandInfo',
        },
    },
    'MultiFrequencyBandListNR_SIB_v1760': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NR_MultiBandInfo_v1760',
        },
    },
    'NID_r16': {
        'k': 'bits',
        'size': [44, 44],
        'ext': False,
    },
    'NPN_IdentityInfoList_r16': {
        'k': 'seqof',
        'size': [1, 12],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NPN_IdentityInfo_r16',
        },
    },
    'NPN_IdentityInfo_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'npn-IdentityList-r16',
                {
                    'k': 'seqof',
                    'size': [1, 12],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'NPN_Identity_r16',
                    },
                },
                False,
                None,
            ],
            [
                'trackingAreaCode-r16',
                {
                    'k': 'ref',
                    't': 'TrackingAreaCode',
                },
                False,
                None,
            ],
            [
                'ranac-r16',
                {
                    'k': 'ref',
                    't': 'RAN_AreaCode',
                },
                True,
                None,
            ],
            [
                'cellIdentity-r16',
                {
                    'k': 'ref',
                    't': 'CellIdentity',
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
                'iab-Support-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['gNB-ID-Length-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'gNB-ID-Length-r17',
                            {
                                'k': 'int',
                                'lb': 22,
                                'ub': 32,
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
                'names': ['mobileIAB-Support-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'mobileIAB-Support-r18',
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
    'NPN_Identity_r16': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'pni-npn-r16',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'plmn-Identity-r16',
                            {
                                'k': 'ref',
                                't': 'PLMN_Identity',
                            },
                            False,
                            None,
                        ],
                        [
                            'cag-IdentityList-r16',
                            {
                                'k': 'seqof',
                                'size': [1, 12],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'CAG_IdentityInfo_r16',
                                },
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            ],
            [
                'snpn-r16',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'plmn-Identity-r16',
                            {
                                'k': 'ref',
                                't': 'PLMN_Identity',
                            },
                            False,
                            None,
                        ],
                        [
                            'nid-List-r16',
                            {
                                'k': 'seqof',
                                'size': [1, 12],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'NID_r16',
                                },
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
    'NR_MultiBandInfo': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'freqBandIndicatorNR',
                {
                    'k': 'ref',
                    't': 'FreqBandIndicatorNR',
                },
                True,
                None,
            ],
            [
                'nr-NS-PmaxList',
                {
                    'k': 'ref',
                    't': 'NR_NS_PmaxList',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NR_MultiBandInfoAerial_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'freqBandIndicatorNR-Aerial-r18',
                {
                    'k': 'ref',
                    't': 'FreqBandIndicatorNR',
                },
                True,
                None,
            ],
            [
                'nr-NS-PmaxListAerial-r18',
                {
                    'k': 'ref',
                    't': 'NR_NS_PmaxListAerial_r18',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NR_MultiBandInfo_v1760': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nr-NS-PmaxList-v1760',
                {
                    'k': 'ref',
                    't': 'NR_NS_PmaxList_v1760',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NR_NS_PmaxList': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NR_NS_PmaxValue',
        },
    },
    'NR_NS_PmaxListAerial_r18': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NR_NS_PmaxValueAerial_r18',
        },
    },
    'NR_NS_PmaxList_v1760': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NR_NS_PmaxValue_v1760',
        },
    },
    'NR_NS_PmaxValue': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'additionalPmax',
                {
                    'k': 'ref',
                    't': 'P_Max',
                },
                True,
                None,
            ],
            [
                'additionalSpectrumEmission',
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
    'NR_NS_PmaxValueAerial_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'additionalPmax-r18',
                {
                    'k': 'ref',
                    't': 'P_Max',
                },
                True,
                None,
            ],
            [
                'additionalSpectrumEmission-r18',
                {
                    'k': 'ref',
                    't': 'AdditionalSpectrumEmission_r18',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'NR_NS_PmaxValue_v1760': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'additionalSpectrumEmission-v1760',
                {
                    'k': 'ref',
                    't': 'AdditionalSpectrumEmission_v1760',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NSAG_ID_r17': {
        'k': 'bits',
        'size': [8, 8],
        'ext': False,
    },
    'NSAG_IdentityInfo_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nsag-ID-r17',
                {
                    'k': 'ref',
                    't': 'NSAG_ID_r17',
                },
                False,
                None,
            ],
            [
                'trackingAreaCode-r17',
                {
                    'k': 'ref',
                    't': 'TrackingAreaCode',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NSAG_List_r17': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NSAG_ID_r17',
        },
    },
    'NTN_Config_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'epochTime-r17',
                {
                    'k': 'ref',
                    't': 'EpochTime_r17',
                },
                True,
                None,
            ],
            [
                'ntn-UlSyncValidityDuration-r17',
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
                'cellSpecificKoffset-r17',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 1023,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'kmac-r17',
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
                'ta-Info-r17',
                {
                    'k': 'ref',
                    't': 'TA_Info_r17',
                },
                True,
                None,
            ],
            [
                'ntn-PolarizationDL-r17',
                {
                    'k': 'enum',
                    'names': ['rhcp', 'lhcp', 'linear'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ntn-PolarizationUL-r17',
                {
                    'k': 'enum',
                    'names': ['rhcp', 'lhcp', 'linear'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ephemerisInfo-r17',
                {
                    'k': 'ref',
                    't': 'EphemerisInfo_r17',
                },
                True,
                None,
            ],
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
        ],
        'extadd': [],
    },
    'NTN_CovEnh_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'numberOfMsg4HARQ-ACK-Repetitions-r18',
                {
                    'k': 'bits',
                    'size': [4, 4],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'rsrp-ThresholdMsg4HARQ-ACK-r18',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NTN_NeighCellConfigList_r17': {
        'k': 'seqof',
        'size': [1, 4],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'NTN_NeighCellConfig_r17',
        },
    },
    'NTN_NeighCellConfig_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ntn-Config-r17',
                {
                    'k': 'ref',
                    't': 'NTN_Config_r17',
                },
                True,
                None,
            ],
            [
                'carrierFreq-r17',
                {
                    'k': 'ref',
                    't': 'ARFCN_ValueNR',
                },
                True,
                None,
            ],
            [
                'physCellId-r17',
                {
                    'k': 'ref',
                    't': 'PhysCellId',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'NumberOfMsg3_Repetitions_r17': {
        'k': 'enum',
        'names': ['n1', 'n2', 'n3', 'n4', 'n7', 'n8', 'n12', 'n16'],
        'ext': None,
    },
    'Orbital_r17': {
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
                'meanAnomaly-r17',
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
    'PCCH_Config': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'defaultPagingCycle',
                {
                    'k': 'ref',
                    't': 'PagingCycle',
                },
                False,
                None,
            ],
            [
                'nAndPagingFrameOffset',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'oneT',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'halfT',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1,
                                'ext': False,
                            },
                        ],
                        [
                            'quarterT',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 3,
                                'ext': False,
                            },
                        ],
                        [
                            'oneEighthT',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 7,
                                'ext': False,
                            },
                        ],
                        [
                            'oneSixteenthT',
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
                'ns',
                {
                    'k': 'enum',
                    'names': ['four', 'two', 'one'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'firstPDCCH-MonitoringOccasionOfPO',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'sCS15KHZoneT',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 139,
                                    'ext': False,
                                },
                            },
                        ],
                        [
                            'sCS30KHZoneT-SCS15KHZhalfT',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 279,
                                    'ext': False,
                                },
                            },
                        ],
                        [
                            'sCS60KHZoneT-SCS30KHZhalfT-SCS15KHZquarterT',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 559,
                                    'ext': False,
                                },
                            },
                        ],
                        [
                            'sCS120KHZoneT-SCS60KHZhalfT-SCS30KHZquarterT-SCS15KHZoneEighthT',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 1119,
                                    'ext': False,
                                },
                            },
                        ],
                        [
                            'sCS120KHZhalfT-SCS60KHZquarterT-SCS30KHZoneEighthT-SCS15KHZoneSixteenthT',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 2239,
                                    'ext': False,
                                },
                            },
                        ],
                        [
                            'sCS480KHZoneT-SCS120KHZquarterT-SCS60KHZoneEighthT-SCS30KHZoneSixteenthT',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 4479,
                                    'ext': False,
                                },
                            },
                        ],
                        [
                            'sCS480KHZhalfT-SCS120KHZoneEighthT-SCS60KHZoneSixteenthT',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 8959,
                                    'ext': False,
                                },
                            },
                        ],
                        [
                            'sCS480KHZquarterT-SCS120KHZoneSixteenthT',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 17919,
                                    'ext': False,
                                },
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['nrofPDCCH-MonitoringOccasionPerSSB-InPO-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nrofPDCCH-MonitoringOccasionPerSSB-InPO-r16',
                            {
                                'k': 'int',
                                'lb': 2,
                                'ub': 4,
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
                'names': ['ranPagingInIdlePO-r17', 'firstPDCCH-MonitoringOccasionOfPO-v1710'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ranPagingInIdlePO-r17',
                            {
                                'k': 'enum',
                                'names': ['true'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'firstPDCCH-MonitoringOccasionOfPO-v1710',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'sCS480KHZoneEighthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 35839,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS480KHZoneSixteenthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 71679,
                                                'ext': False,
                                            },
                                        },
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
    'PCI_Range': {
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
                        'n1008',
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
    'PDCCH_ConfigCommon': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'controlResourceSetZero',
                {
                    'k': 'ref',
                    't': 'ControlResourceSetZero',
                },
                True,
                None,
            ],
            [
                'commonControlResourceSet',
                {
                    'k': 'ref',
                    't': 'ControlResourceSet',
                },
                True,
                None,
            ],
            [
                'searchSpaceZero',
                {
                    'k': 'ref',
                    't': 'SearchSpaceZero',
                },
                True,
                None,
            ],
            [
                'commonSearchSpaceList',
                {
                    'k': 'seqof',
                    'size': [1, 4],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SearchSpace',
                    },
                },
                True,
                None,
            ],
            [
                'searchSpaceSIB1',
                {
                    'k': 'ref',
                    't': 'SearchSpaceId',
                },
                True,
                None,
            ],
            [
                'searchSpaceOtherSystemInformation',
                {
                    'k': 'ref',
                    't': 'SearchSpaceId',
                },
                True,
                None,
            ],
            [
                'pagingSearchSpace',
                {
                    'k': 'ref',
                    't': 'SearchSpaceId',
                },
                True,
                None,
            ],
            [
                'ra-SearchSpace',
                {
                    'k': 'ref',
                    't': 'SearchSpaceId',
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['firstPDCCH-MonitoringOccasionOfPO'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'firstPDCCH-MonitoringOccasionOfPO',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'sCS15KHZoneT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 139,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS30KHZoneT-SCS15KHZhalfT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 279,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS60KHZoneT-SCS30KHZhalfT-SCS15KHZquarterT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 559,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS120KHZoneT-SCS60KHZhalfT-SCS30KHZquarterT-SCS15KHZoneEighthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 1119,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS120KHZhalfT-SCS60KHZquarterT-SCS30KHZoneEighthT-SCS15KHZoneSixteenthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 2239,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS120KHZquarterT-SCS60KHZoneEighthT-SCS30KHZoneSixteenthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 4479,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS120KHZoneEighthT-SCS60KHZoneSixteenthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 8959,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS120KHZoneSixteenthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 17919,
                                                'ext': False,
                                            },
                                        },
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
            {
                'k': 'extgrp',
                'names': ['commonSearchSpaceListExt-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'commonSearchSpaceListExt-r16',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'SearchSpaceExt_r16',
                                },
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
                    'sdt-SearchSpace-r17',
                    'searchSpaceMCCH-r17',
                    'searchSpaceMTCH-r17',
                    'commonSearchSpaceListExt2-r17',
                    'firstPDCCH-MonitoringOccasionOfPO-v1710',
                    'pei-ConfigBWP-r17',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'sdt-SearchSpace-r17',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'newSearchSpace',
                                        {
                                            'k': 'ref',
                                            't': 'SearchSpace',
                                        },
                                    ],
                                    [
                                        'existingSearchSpace',
                                        {
                                            'k': 'ref',
                                            't': 'SearchSpaceId',
                                        },
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'searchSpaceMCCH-r17',
                            {
                                'k': 'ref',
                                't': 'SearchSpaceId',
                            },
                            True,
                            None,
                        ],
                        [
                            'searchSpaceMTCH-r17',
                            {
                                'k': 'ref',
                                't': 'SearchSpaceId',
                            },
                            True,
                            None,
                        ],
                        [
                            'commonSearchSpaceListExt2-r17',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'SearchSpaceExt_v1700',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'firstPDCCH-MonitoringOccasionOfPO-v1710',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'sCS480KHZoneEighthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 35839,
                                                'ext': False,
                                            },
                                        },
                                    ],
                                    [
                                        'sCS480KHZoneSixteenthT',
                                        {
                                            'k': 'seqof',
                                            'size': [1, 4],
                                            'ext': False,
                                            'of': {
                                                'k': 'int',
                                                'lb': 0,
                                                'ub': 71679,
                                                'ext': False,
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
                            'pei-ConfigBWP-r17',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'pei-SearchSpace-r17',
                                        {
                                            'k': 'ref',
                                            't': 'SearchSpaceId',
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'firstPDCCH-MonitoringOccasionOfPEI-O-r17',
                                        {
                                            'k': 'choice',
                                            'ext': False,
                                            'alts': [
                                                [
                                                    'sCS15KHZoneT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 139,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS30KHZoneT-SCS15KHZhalfT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 279,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS60KHZoneT-SCS30KHZhalfT-SCS15KHZquarterT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 559,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS120KHZoneT-SCS60KHZhalfT-SCS30KHZquarterT-SCS15KHZoneEighthT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 1119,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS120KHZhalfT-SCS60KHZquarterT-SCS30KHZoneEighthT-SCS15KHZoneSixteenthT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 2239,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS480KHZoneT-SCS120KHZquarterT-SCS60KHZoneEighthT-SCS30KHZoneSixteenthT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 4479,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS480KHZhalfT-SCS120KHZoneEighthT-SCS60KHZoneSixteenthT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 8959,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS480KHZquarterT-SCS120KHZoneSixteenthT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 17919,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS480KHZoneEighthT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 35839,
                                                            'ext': False,
                                                        },
                                                    },
                                                ],
                                                [
                                                    'sCS480KHZoneSixteenthT',
                                                    {
                                                        'k': 'seqof',
                                                        'size': [1, 4],
                                                        'ext': False,
                                                        'of': {
                                                            'k': 'int',
                                                            'lb': 0,
                                                            'ub': 71679,
                                                            'ext': False,
                                                        },
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
                            True,
                            None,
                        ],
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['followUnifiedTCI-State-v1720'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'followUnifiedTCI-State-v1720',
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
                'names': [
                    'applyIndicatedTCI-State-r18',
                    'commonSearchSpaceListExt-r18',
                    'searchSpaceMulticastMCCH-r18',
                    'searchSpaceMulticastMTCH-r18',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'applyIndicatedTCI-State-r18',
                            {
                                'k': 'enum',
                                'names': ['first', 'second', 'both', 'none'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'commonSearchSpaceListExt-r18',
                            {
                                'k': 'seqof',
                                'size': [1, 4],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'SearchSpaceExt_v1800',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'searchSpaceMulticastMCCH-r18',
                            {
                                'k': 'ref',
                                't': 'SearchSpaceId',
                            },
                            True,
                            None,
                        ],
                        [
                            'searchSpaceMulticastMTCH-r18',
                            {
                                'k': 'ref',
                                't': 'SearchSpaceId',
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
    'PDCCH_ConfigSIB1': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'controlResourceSetZero',
                {
                    'k': 'ref',
                    't': 'ControlResourceSetZero',
                },
                False,
                None,
            ],
            [
                'searchSpaceZero',
                {
                    'k': 'ref',
                    't': 'SearchSpaceZero',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'PDSCH_ConfigBroadcast_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'pdschConfigList-r17',
                {
                    'k': 'seqof',
                    'size': [1, 16],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PDSCH_ConfigPTM_r17',
                    },
                },
                False,
                None,
            ],
            [
                'pdsch-TimeDomainAllocationList-r17',
                {
                    'k': 'ref',
                    't': 'PDSCH_TimeDomainResourceAllocationList_r16',
                },
                True,
                None,
            ],
            [
                'rateMatchPatternToAddModList-r17',
                {
                    'k': 'seqof',
                    'size': [1, 4],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'RateMatchPattern',
                    },
                },
                True,
                None,
            ],
            [
                'lte-CRS-ToMatchAround-r17',
                {
                    'k': 'ref',
                    't': 'RateMatchPatternLTE_CRS',
                },
                True,
                None,
            ],
            [
                'mcs-Table-r17',
                {
                    'k': 'enum',
                    'names': ['qam256', 'qam64LowSE'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'xOverhead-r17',
                {
                    'k': 'enum',
                    'names': ['xOh6', 'xOh12', 'xOh18'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PDSCH_ConfigCommon': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'pdsch-TimeDomainAllocationList',
                {
                    'k': 'ref',
                    't': 'PDSCH_TimeDomainResourceAllocationList',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PDSCH_ConfigPTM_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'dataScramblingIdentityPDSCH-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1023,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'dmrs-ScramblingID0-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 65535,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'pdsch-AggregationFactor-r17',
                {
                    'k': 'enum',
                    'names': ['n2', 'n4', 'n8'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PDSCH_TimeDomainResourceAllocation': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'k0',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 32,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'mappingType',
                {
                    'k': 'enum',
                    'names': ['typeA', 'typeB'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'startSymbolAndLength',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 127,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'PDSCH_TimeDomainResourceAllocationList': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PDSCH_TimeDomainResourceAllocation',
        },
    },
    'PDSCH_TimeDomainResourceAllocationList_r16': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PDSCH_TimeDomainResourceAllocation_r16',
        },
    },
    'PDSCH_TimeDomainResourceAllocation_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'k0-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 32,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'mappingType-r16',
                {
                    'k': 'enum',
                    'names': ['typeA', 'typeB'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'startSymbolAndLength-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 127,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'repetitionNumber-r16',
                {
                    'k': 'enum',
                    'names': ['n2', 'n3', 'n4', 'n5', 'n6', 'n7', 'n8', 'n16'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['k0-v1710'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'k0-v1710',
                            {
                                'k': 'int',
                                'lb': 33,
                                'ub': 128,
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
                'names': ['repetitionNumber-v1730'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'repetitionNumber-v1730',
                            {
                                'k': 'enum',
                                'names': ['n2', 'n3', 'n4', 'n5', 'n6', 'n7', 'n8', 'n16'],
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
    'PEI_Config_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'po-NumPerPEI-r17',
                {
                    'k': 'enum',
                    'names': ['po1', 'po2', 'po4', 'po8'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'payloadSizeDCI-2-7-r17',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 43,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'pei-FrameOffset-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 16,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'subgroupConfig-r17',
                {
                    'k': 'ref',
                    't': 'SubgroupConfig_r17',
                },
                False,
                None,
            ],
            [
                'lastUsedCellOnly-r17',
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
    'PLMN_IdentityInfo': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'plmn-IdentityList',
                {
                    'k': 'seqof',
                    'size': [1, 12],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PLMN_Identity',
                    },
                },
                False,
                None,
            ],
            [
                'trackingAreaCode',
                {
                    'k': 'ref',
                    't': 'TrackingAreaCode',
                },
                True,
                None,
            ],
            [
                'ranac',
                {
                    'k': 'ref',
                    't': 'RAN_AreaCode',
                },
                True,
                None,
            ],
            [
                'cellIdentity',
                {
                    'k': 'ref',
                    't': 'CellIdentity',
                },
                False,
                None,
            ],
            [
                'cellReservedForOperatorUse',
                {
                    'k': 'enum',
                    'names': ['reserved', 'notReserved'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['iab-Support-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'iab-Support-r16',
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
                'names': ['trackingAreaList-r17', 'gNB-ID-Length-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'trackingAreaList-r17',
                            {
                                'k': 'seqof',
                                'size': [1, 12],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'TrackingAreaCode',
                                },
                            },
                            True,
                            None,
                        ],
                        [
                            'gNB-ID-Length-r17',
                            {
                                'k': 'int',
                                'lb': 22,
                                'ub': 32,
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
                'names': ['mobileIAB-Support-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'mobileIAB-Support-r18',
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
    'PLMN_IdentityInfoList': {
        'k': 'seqof',
        'size': [1, 12],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PLMN_IdentityInfo',
        },
    },
    'PUCCH_ConfigCommon': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'pucch-ResourceCommon',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 15,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'pucch-GroupHopping',
                {
                    'k': 'enum',
                    'names': ['neither', 'enable', 'disable'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'hoppingId',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 1023,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'p0-nominal',
                {
                    'k': 'int',
                    'lb': -202,
                    'ub': 24,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': [
                    'nrofPRBs',
                    'intra-SlotFH-r17',
                    'pucch-ResourceCommonRedCap-r17',
                    'additionalPRBOffset-r17',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'nrofPRBs',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 16,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'intra-SlotFH-r17',
                            {
                                'k': 'enum',
                                'names': ['fromLowerEdge', 'fromUpperEdge'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'pucch-ResourceCommonRedCap-r17',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 15,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'additionalPRBOffset-r17',
                            {
                                'k': 'enum',
                                'names': ['n2', 'n3', 'n4', 'n6', 'n8', 'n9', 'n10', 'n12'],
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
    'PUSCH_ConfigCommon': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'groupHoppingEnabledTransformPrecoding',
                {
                    'k': 'enum',
                    'names': ['enabled'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'pusch-TimeDomainAllocationList',
                {
                    'k': 'ref',
                    't': 'PUSCH_TimeDomainResourceAllocationList',
                },
                True,
                None,
            ],
            [
                'msg3-DeltaPreamble',
                {
                    'k': 'int',
                    'lb': -1,
                    'ub': 6,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'p0-NominalWithGrant',
                {
                    'k': 'int',
                    'lb': -202,
                    'ub': 24,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'PUSCH_TimeDomainResourceAllocation': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'k2',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 32,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'mappingType',
                {
                    'k': 'enum',
                    'names': ['typeA', 'typeB'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'startSymbolAndLength',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 127,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'PUSCH_TimeDomainResourceAllocationList': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PUSCH_TimeDomainResourceAllocation',
        },
    },
    'P_Max': {
        'k': 'int',
        'lb': -30,
        'ub': 33,
        'ext': False,
    },
    'PagingCycle': {
        'k': 'enum',
        'names': ['rf32', 'rf64', 'rf128', 'rf256'],
        'ext': None,
    },
    'PhysCellId': {
        'k': 'int',
        'lb': 0,
        'ub': 1007,
        'ext': False,
    },
    'PosSIB_MappingInfo_r16': {
        'k': 'seqof',
        'size': [1, 32],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PosSIB_Type_r16',
        },
    },
    'PosSIB_Type_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'encrypted-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'gnss-id-r16',
                {
                    'k': 'ref',
                    't': 'GNSS_ID_r16',
                },
                True,
                None,
            ],
            [
                'sbas-id-r16',
                {
                    'k': 'ref',
                    't': 'SBAS_ID_r16',
                },
                True,
                None,
            ],
            [
                'posSibType-r16',
                {
                    'k': 'enum',
                    'names': [
                        'posSibType1-1',
                        'posSibType1-2',
                        'posSibType1-3',
                        'posSibType1-4',
                        'posSibType1-5',
                        'posSibType1-6',
                        'posSibType1-7',
                        'posSibType1-8',
                        'posSibType2-1',
                        'posSibType2-2',
                        'posSibType2-3',
                        'posSibType2-4',
                        'posSibType2-5',
                        'posSibType2-6',
                        'posSibType2-7',
                        'posSibType2-8',
                        'posSibType2-9',
                        'posSibType2-10',
                        'posSibType2-11',
                        'posSibType2-12',
                        'posSibType2-13',
                        'posSibType2-14',
                        'posSibType2-15',
                        'posSibType2-16',
                        'posSibType2-17',
                        'posSibType2-18',
                        'posSibType2-19',
                        'posSibType2-20',
                        'posSibType2-21',
                        'posSibType2-22',
                        'posSibType2-23',
                        'posSibType3-1',
                        'posSibType4-1',
                        'posSibType5-1',
                        'posSibType6-1',
                        'posSibType6-2',
                        'posSibType6-3',
                    ],
                    'ext': [],
                },
                False,
                None,
            ],
            [
                'areaScope-r16',
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
    'PosSI_SchedulingInfo_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'posSchedulingInfoList-r16',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PosSchedulingInfo_r16',
                    },
                },
                False,
                None,
            ],
            [
                'posSI-RequestConfig-r16',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfig',
                },
                True,
                None,
            ],
            [
                'posSI-RequestConfigSUL-r16',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfig',
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['posSI-RequestConfigRedCap-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'posSI-RequestConfigRedCap-r17',
                            {
                                'k': 'ref',
                                't': 'SI_RequestConfig',
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
                    'posSI-RequestConfigMSG1-Repetition-r18',
                    'posSI-RequestConfigSUL-MSG1-Repetition-r18',
                    'posSI-RequestConfigRedCap-MSG1-Repetition-r18',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'posSI-RequestConfigMSG1-Repetition-r18',
                            {
                                'k': 'ref',
                                't': 'SI_RequestConfigRepetition_r18',
                            },
                            True,
                            None,
                        ],
                        [
                            'posSI-RequestConfigSUL-MSG1-Repetition-r18',
                            {
                                'k': 'ref',
                                't': 'SI_RequestConfigRepetition_r18',
                            },
                            True,
                            None,
                        ],
                        [
                            'posSI-RequestConfigRedCap-MSG1-Repetition-r18',
                            {
                                'k': 'ref',
                                't': 'SI_RequestConfigRepetition_r18',
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
    'PosSchedulingInfo_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'offsetToSI-Used-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'posSI-Periodicity-r16',
                {
                    'k': 'enum',
                    'names': ['rf8', 'rf16', 'rf32', 'rf64', 'rf128', 'rf256', 'rf512'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'posSI-BroadcastStatus-r16',
                {
                    'k': 'enum',
                    'names': ['broadcasting', 'notBroadcasting'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'posSIB-MappingInfo-r16',
                {
                    'k': 'ref',
                    't': 'PosSIB_MappingInfo_r16',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'PosSystemInformation_r16_IEs': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'posSIB-TypeAndInfo-r16',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'choice',
                        'ext': True,
                        'alts': [
                            [
                                'posSib1-1-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-2-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-3-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-4-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-5-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-6-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-7-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-8-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-1-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-2-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-3-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-4-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-5-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-6-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-7-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-8-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-9-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-10-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-11-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-12-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-13-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-14-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-15-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-16-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-17-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-18-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-19-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-20-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-21-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-22-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-23-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib3-1-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib4-1-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib5-1-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib6-1-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib6-2-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib6-3-r16',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                        ],
                        'extadd': [
                            [
                                'posSib1-9-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-10-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-24-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-25-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib6-4-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib6-5-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib6-6-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-17a-v1770',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-18a-v1770',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-20a-v1770',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-11-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib1-12-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-26-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib2-27-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib6-7-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib7-1-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib7-2-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib7-3-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
                                },
                            ],
                            [
                                'posSib7-4-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIBpos_r16',
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
    'PositionStateVector_r17': {
        'k': 'int',
        'lb': -33554432,
        'ub': 33554431,
        'ext': False,
    },
    'PositionVelocity_r17': {
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
    'Q_QualMin': {
        'k': 'int',
        'lb': -43,
        'ub': -12,
        'ext': False,
    },
    'Q_RxLevMin': {
        'k': 'int',
        'lb': -70,
        'ub': -22,
        'ext': False,
    },
    'RACH_ConfigCommon': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'rach-ConfigGeneric',
                {
                    'k': 'ref',
                    't': 'RACH_ConfigGeneric',
                },
                False,
                None,
            ],
            [
                'totalNumberOfRA-Preambles',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 63,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'ssb-perRACH-OccasionAndCB-PreamblesPerSSB',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'oneEighth',
                            {
                                'k': 'enum',
                                'names': [
                                    'n4',
                                    'n8',
                                    'n12',
                                    'n16',
                                    'n20',
                                    'n24',
                                    'n28',
                                    'n32',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n48',
                                    'n52',
                                    'n56',
                                    'n60',
                                    'n64',
                                ],
                                'ext': None,
                            },
                        ],
                        [
                            'oneFourth',
                            {
                                'k': 'enum',
                                'names': [
                                    'n4',
                                    'n8',
                                    'n12',
                                    'n16',
                                    'n20',
                                    'n24',
                                    'n28',
                                    'n32',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n48',
                                    'n52',
                                    'n56',
                                    'n60',
                                    'n64',
                                ],
                                'ext': None,
                            },
                        ],
                        [
                            'oneHalf',
                            {
                                'k': 'enum',
                                'names': [
                                    'n4',
                                    'n8',
                                    'n12',
                                    'n16',
                                    'n20',
                                    'n24',
                                    'n28',
                                    'n32',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n48',
                                    'n52',
                                    'n56',
                                    'n60',
                                    'n64',
                                ],
                                'ext': None,
                            },
                        ],
                        [
                            'one',
                            {
                                'k': 'enum',
                                'names': [
                                    'n4',
                                    'n8',
                                    'n12',
                                    'n16',
                                    'n20',
                                    'n24',
                                    'n28',
                                    'n32',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n48',
                                    'n52',
                                    'n56',
                                    'n60',
                                    'n64',
                                ],
                                'ext': None,
                            },
                        ],
                        [
                            'two',
                            {
                                'k': 'enum',
                                'names': ['n4', 'n8', 'n12', 'n16', 'n20', 'n24', 'n28', 'n32'],
                                'ext': None,
                            },
                        ],
                        [
                            'four',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 16,
                                'ext': False,
                            },
                        ],
                        [
                            'eight',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 8,
                                'ext': False,
                            },
                        ],
                        [
                            'sixteen',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 4,
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'groupBconfigured',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ra-Msg3SizeGroupA',
                            {
                                'k': 'enum',
                                'names': [
                                    'b56',
                                    'b144',
                                    'b208',
                                    'b256',
                                    'b282',
                                    'b480',
                                    'b640',
                                    'b800',
                                    'b1000',
                                    'b72',
                                    'spare6',
                                    'spare5',
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
                            'messagePowerOffsetGroupB',
                            {
                                'k': 'enum',
                                'names': ['minusinfinity', 'dB0', 'dB5', 'dB8', 'dB10', 'dB12', 'dB15', 'dB18'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'numberOfRA-PreamblesGroupA',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 64,
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
                'ra-ContentionResolutionTimer',
                {
                    'k': 'enum',
                    'names': ['sf8', 'sf16', 'sf24', 'sf32', 'sf40', 'sf48', 'sf56', 'sf64'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'rsrp-ThresholdSSB',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'rsrp-ThresholdSSB-SUL',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'prach-RootSequenceIndex',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'l839',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 837,
                                'ext': False,
                            },
                        ],
                        [
                            'l139',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 137,
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
                'msg1-SubcarrierSpacing',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                True,
                None,
            ],
            [
                'restrictedSetConfig',
                {
                    'k': 'enum',
                    'names': ['unrestrictedSet', 'restrictedSetTypeA', 'restrictedSetTypeB'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'msg3-transformPrecoder',
                {
                    'k': 'enum',
                    'names': ['enabled'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': [
                    'ra-PrioritizationForAccessIdentity-r16',
                    'prach-RootSequenceIndex-r16',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ra-PrioritizationForAccessIdentity-r16',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'ra-Prioritization-r16',
                                        {
                                            'k': 'ref',
                                            't': 'RA_Prioritization',
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'ra-PrioritizationForAI-r16',
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
                            True,
                            None,
                        ],
                        [
                            'prach-RootSequenceIndex-r16',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'l571',
                                        {
                                            'k': 'int',
                                            'lb': 0,
                                            'ub': 569,
                                            'ext': False,
                                        },
                                    ],
                                    [
                                        'l1151',
                                        {
                                            'k': 'int',
                                            'lb': 0,
                                            'ub': 1149,
                                            'ext': False,
                                        },
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
            {
                'k': 'extgrp',
                'names': [
                    'ra-PrioritizationForSlicing-r17',
                    'featureCombinationPreamblesList-r17',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ra-PrioritizationForSlicing-r17',
                            {
                                'k': 'ref',
                                't': 'RA_PrioritizationForSlicing_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'featureCombinationPreamblesList-r17',
                            {
                                'k': 'seqof',
                                'size': [1, 256],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'FeatureCombinationPreambles_r17',
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
    'RACH_ConfigCommonTwoStepRA_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'rach-ConfigGenericTwoStepRA-r16',
                {
                    'k': 'ref',
                    't': 'RACH_ConfigGenericTwoStepRA_r16',
                },
                False,
                None,
            ],
            [
                'msgA-TotalNumberOfRA-Preambles-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 63,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-SSB-PerRACH-OccasionAndCB-PreamblesPerSSB-r16',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'oneEighth',
                            {
                                'k': 'enum',
                                'names': [
                                    'n4',
                                    'n8',
                                    'n12',
                                    'n16',
                                    'n20',
                                    'n24',
                                    'n28',
                                    'n32',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n48',
                                    'n52',
                                    'n56',
                                    'n60',
                                    'n64',
                                ],
                                'ext': None,
                            },
                        ],
                        [
                            'oneFourth',
                            {
                                'k': 'enum',
                                'names': [
                                    'n4',
                                    'n8',
                                    'n12',
                                    'n16',
                                    'n20',
                                    'n24',
                                    'n28',
                                    'n32',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n48',
                                    'n52',
                                    'n56',
                                    'n60',
                                    'n64',
                                ],
                                'ext': None,
                            },
                        ],
                        [
                            'oneHalf',
                            {
                                'k': 'enum',
                                'names': [
                                    'n4',
                                    'n8',
                                    'n12',
                                    'n16',
                                    'n20',
                                    'n24',
                                    'n28',
                                    'n32',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n48',
                                    'n52',
                                    'n56',
                                    'n60',
                                    'n64',
                                ],
                                'ext': None,
                            },
                        ],
                        [
                            'one',
                            {
                                'k': 'enum',
                                'names': [
                                    'n4',
                                    'n8',
                                    'n12',
                                    'n16',
                                    'n20',
                                    'n24',
                                    'n28',
                                    'n32',
                                    'n36',
                                    'n40',
                                    'n44',
                                    'n48',
                                    'n52',
                                    'n56',
                                    'n60',
                                    'n64',
                                ],
                                'ext': None,
                            },
                        ],
                        [
                            'two',
                            {
                                'k': 'enum',
                                'names': ['n4', 'n8', 'n12', 'n16', 'n20', 'n24', 'n28', 'n32'],
                                'ext': None,
                            },
                        ],
                        [
                            'four',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 16,
                                'ext': False,
                            },
                        ],
                        [
                            'eight',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 8,
                                'ext': False,
                            },
                        ],
                        [
                            'sixteen',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 4,
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'msgA-CB-PreamblesPerSSB-PerSharedRO-r16',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 60,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-SSB-SharedRO-MaskIndex-r16',
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
                'groupB-ConfiguredTwoStepRA-r16',
                {
                    'k': 'ref',
                    't': 'GroupB_ConfiguredTwoStepRA_r16',
                },
                True,
                None,
            ],
            [
                'msgA-PRACH-RootSequenceIndex-r16',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'l839',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 837,
                                'ext': False,
                            },
                        ],
                        [
                            'l139',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 137,
                                'ext': False,
                            },
                        ],
                        [
                            'l571',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 569,
                                'ext': False,
                            },
                        ],
                        [
                            'l1151',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1149,
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'msgA-TransMax-r16',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n4', 'n6', 'n8', 'n10', 'n20', 'n50', 'n100', 'n200'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'msgA-RSRP-Threshold-r16',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'msgA-RSRP-ThresholdSSB-r16',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'msgA-SubcarrierSpacing-r16',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                True,
                None,
            ],
            [
                'msgA-RestrictedSetConfig-r16',
                {
                    'k': 'enum',
                    'names': ['unrestrictedSet', 'restrictedSetTypeA', 'restrictedSetTypeB'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ra-PrioritizationForAccessIdentityTwoStep-r16',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ra-Prioritization-r16',
                            {
                                'k': 'ref',
                                't': 'RA_Prioritization',
                            },
                            False,
                            None,
                        ],
                        [
                            'ra-PrioritizationForAI-r16',
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
                True,
                None,
            ],
            [
                'ra-ContentionResolutionTimer-r16',
                {
                    'k': 'enum',
                    'names': ['sf8', 'sf16', 'sf24', 'sf32', 'sf40', 'sf48', 'sf56', 'sf64'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': [
                    'ra-PrioritizationForSlicingTwoStep-r17',
                    'featureCombinationPreamblesList-r17',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ra-PrioritizationForSlicingTwoStep-r17',
                            {
                                'k': 'ref',
                                't': 'RA_PrioritizationForSlicing_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'featureCombinationPreamblesList-r17',
                            {
                                'k': 'seqof',
                                'size': [1, 256],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'FeatureCombinationPreambles_r17',
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
    'RACH_ConfigGeneric': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'prach-ConfigurationIndex',
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
                'msg1-FDM',
                {
                    'k': 'enum',
                    'names': ['one', 'two', 'four', 'eight'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'msg1-FrequencyStart',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 274,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'zeroCorrelationZoneConfig',
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
                'preambleReceivedTargetPower',
                {
                    'k': 'int',
                    'lb': -202,
                    'ub': -60,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'preambleTransMax',
                {
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
                False,
                None,
            ],
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
                'ra-ResponseWindow',
                {
                    'k': 'enum',
                    'names': ['sl1', 'sl2', 'sl4', 'sl8', 'sl10', 'sl20', 'sl40', 'sl80'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': [
                    'prach-ConfigurationPeriodScaling-IAB-r16',
                    'prach-ConfigurationFrameOffset-IAB-r16',
                    'prach-ConfigurationSOffset-IAB-r16',
                    'ra-ResponseWindow-v1610',
                    'prach-ConfigurationIndex-v1610',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'prach-ConfigurationPeriodScaling-IAB-r16',
                            {
                                'k': 'enum',
                                'names': ['scf1', 'scf2', 'scf4', 'scf8', 'scf16', 'scf32', 'scf64'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'prach-ConfigurationFrameOffset-IAB-r16',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 63,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'prach-ConfigurationSOffset-IAB-r16',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 39,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'ra-ResponseWindow-v1610',
                            {
                                'k': 'enum',
                                'names': ['sl60', 'sl160'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'prach-ConfigurationIndex-v1610',
                            {
                                'k': 'int',
                                'lb': 256,
                                'ub': 262,
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
                'names': ['ra-ResponseWindow-v1700'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ra-ResponseWindow-v1700',
                            {
                                'k': 'enum',
                                'names': ['sl240', 'sl320', 'sl640', 'sl960', 'sl1280', 'sl1920', 'sl2560'],
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
    'RACH_ConfigGenericTwoStepRA_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'msgA-PRACH-ConfigurationIndex-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 262,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-RO-FDM-r16',
                {
                    'k': 'enum',
                    'names': ['one', 'two', 'four', 'eight'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'msgA-RO-FrequencyStart-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 274,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-ZeroCorrelationZoneConfig-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 15,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgA-PreamblePowerRampingStep-r16',
                {
                    'k': 'enum',
                    'names': ['dB0', 'dB2', 'dB4', 'dB6'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'msgA-PreambleReceivedTargetPower-r16',
                {
                    'k': 'int',
                    'lb': -202,
                    'ub': -60,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'msgB-ResponseWindow-r16',
                {
                    'k': 'enum',
                    'names': [
                        'sl1',
                        'sl2',
                        'sl4',
                        'sl8',
                        'sl10',
                        'sl20',
                        'sl40',
                        'sl80',
                        'sl160',
                        'sl320',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'preambleTransMax-r16',
                {
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
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['msgB-ResponseWindow-v1700'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'msgB-ResponseWindow-v1700',
                            {
                                'k': 'enum',
                                'names': ['sl240', 'sl640', 'sl960', 'sl1280', 'sl1920', 'sl2560'],
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
    'RACH_ConfigTwoTA_r18': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'additionalPCI-andRACH-Index-r18',
                {
                    'k': 'ref',
                    't': 'AdditionalPCIIndex_r17',
                },
                False,
                None,
            ],
            [
                'rach-ConfigGeneric-r18',
                {
                    'k': 'ref',
                    't': 'RACH_ConfigGeneric',
                },
                False,
                None,
            ],
            [
                'ssb-perRACH-Occasion-r18',
                {
                    'k': 'enum',
                    'names': [
                        'oneEighth',
                        'oneFourth',
                        'oneHalf',
                        'one',
                        'two',
                        'four',
                        'eight',
                        'sixteen',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'prach-RootSequenceIndex-r18',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'l839',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 837,
                                'ext': False,
                            },
                        ],
                        [
                            'l139',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 137,
                                'ext': False,
                            },
                        ],
                        [
                            'l571',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 569,
                                'ext': False,
                            },
                        ],
                        [
                            'l1151',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1149,
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
                'msg1-SubcarrierSpacing-r18',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                True,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['twoTA-restrictedSetConfig-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'twoTA-restrictedSetConfig-r18',
                            {
                                'k': 'enum',
                                'names': ['unrestrictedSet', 'restrictedSetTypeA', 'restrictedSetTypeB'],
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
    'RAN_AreaCode': {
        'k': 'int',
        'lb': 0,
        'ub': 255,
        'ext': False,
    },
    'RA_Prioritization': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'powerRampingStepHighPriority',
                {
                    'k': 'enum',
                    'names': ['dB0', 'dB2', 'dB4', 'dB6'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'scalingFactorBI',
                {
                    'k': 'enum',
                    'names': ['zero', 'dot25', 'dot5', 'dot75'],
                    'ext': None,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'RA_PrioritizationForSlicing_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'ra-PrioritizationSliceInfoList-r17',
                {
                    'k': 'ref',
                    't': 'RA_PrioritizationSliceInfoList_r17',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'RA_PrioritizationSliceInfoList_r17': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'RA_PrioritizationSliceInfo_r17',
        },
    },
    'RA_PrioritizationSliceInfo_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'nsag-ID-List-r17',
                {
                    'k': 'seqof',
                    'size': [1, 8],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'NSAG_ID_r17',
                    },
                },
                False,
                None,
            ],
            [
                'ra-Prioritization-r17',
                {
                    'k': 'ref',
                    't': 'RA_Prioritization',
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
        'ub': 127,
        'ext': False,
    },
    'RSRP_RangeEUTRA': {
        'k': 'int',
        'lb': 0,
        'ub': 97,
        'ext': False,
    },
    'RSRQ_Range': {
        'k': 'int',
        'lb': 0,
        'ub': 127,
        'ext': False,
    },
    'RSRQ_RangeEUTRA_r16': {
        'k': 'int',
        'lb': -30,
        'ub': 46,
        'ext': False,
    },
    'RangeToBestCell': {
        'k': 'ref',
        't': 'Q_OffsetRange',
    },
    'RateMatchPattern': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'rateMatchPatternId',
                {
                    'k': 'ref',
                    't': 'RateMatchPatternId',
                },
                False,
                None,
            ],
            [
                'patternType',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'bitmaps',
                            {
                                'k': 'seq',
                                'ext': True,
                                'comp': [
                                    [
                                        'resourceBlocks',
                                        {
                                            'k': 'bits',
                                            'size': [275, 275],
                                            'ext': False,
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'symbolsInResourceBlock',
                                        {
                                            'k': 'choice',
                                            'ext': False,
                                            'alts': [
                                                [
                                                    'oneSlot',
                                                    {
                                                        'k': 'bits',
                                                        'size': [14, 14],
                                                        'ext': False,
                                                    },
                                                ],
                                                [
                                                    'twoSlots',
                                                    {
                                                        'k': 'bits',
                                                        'size': [28, 28],
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
                                        'periodicityAndPattern',
                                        {
                                            'k': 'choice',
                                            'ext': False,
                                            'alts': [
                                                [
                                                    'n2',
                                                    {
                                                        'k': 'bits',
                                                        'size': [2, 2],
                                                        'ext': False,
                                                    },
                                                ],
                                                [
                                                    'n4',
                                                    {
                                                        'k': 'bits',
                                                        'size': [4, 4],
                                                        'ext': False,
                                                    },
                                                ],
                                                [
                                                    'n5',
                                                    {
                                                        'k': 'bits',
                                                        'size': [5, 5],
                                                        'ext': False,
                                                    },
                                                ],
                                                [
                                                    'n8',
                                                    {
                                                        'k': 'bits',
                                                        'size': [8, 8],
                                                        'ext': False,
                                                    },
                                                ],
                                                [
                                                    'n10',
                                                    {
                                                        'k': 'bits',
                                                        'size': [10, 10],
                                                        'ext': False,
                                                    },
                                                ],
                                                [
                                                    'n20',
                                                    {
                                                        'k': 'bits',
                                                        'size': [20, 20],
                                                        'ext': False,
                                                    },
                                                ],
                                                [
                                                    'n40',
                                                    {
                                                        'k': 'bits',
                                                        'size': [40, 40],
                                                        'ext': False,
                                                    },
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
                        ],
                        [
                            'controlResourceSet',
                            {
                                'k': 'ref',
                                't': 'ControlResourceSetId',
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'subcarrierSpacing',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                True,
                None,
            ],
            [
                'dummy',
                {
                    'k': 'enum',
                    'names': ['dynamic', 'semiStatic'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['controlResourceSet-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'controlResourceSet-r16',
                            {
                                'k': 'ref',
                                't': 'ControlResourceSetId_r16',
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
    'RateMatchPatternId': {
        'k': 'int',
        'lb': 0,
        'ub': 3,
        'ext': False,
    },
    'RateMatchPatternLTE_CRS': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'carrierFreqDL',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 16383,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'carrierBandwidthDL',
                {
                    'k': 'enum',
                    'names': ['n6', 'n15', 'n25', 'n50', 'n75', 'n100', 'spare2', 'spare1'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'mbsfn-SubframeConfigList',
                {
                    'k': 'ref',
                    't': 'EUTRA_MBSFN_SubframeConfigList',
                },
                True,
                None,
            ],
            [
                'nrofCRS-Ports',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n4'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'v-Shift',
                {
                    'k': 'enum',
                    'names': ['n0', 'n1', 'n2', 'n3', 'n4', 'n5'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'RedCap_ConfigCommonSIB_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'halfDuplexRedCapAllowed-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'cellBarredRedCap-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'cellBarredRedCap1Rx-r17',
                            {
                                'k': 'enum',
                                'names': ['barred', 'notBarred'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'cellBarredRedCap2Rx-r17',
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
        ],
        'extadd': [],
    },
    'ReferenceLocation_r17': {
        'k': 'octets',
        'size': None,
        'ext': False,
        'containing': None,
    },
    'ReferenceTimeInfo_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'time-r16',
                {
                    'k': 'ref',
                    't': 'ReferenceTime_r16',
                },
                False,
                None,
            ],
            [
                'uncertainty-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 32767,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'timeInfoType-r16',
                {
                    'k': 'enum',
                    'names': ['localClock'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'referenceSFN-r16',
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
    'ReferenceTime_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'refDays-r16',
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
                'refSeconds-r16',
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
                'refMilliSeconds-r16',
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
                'refTenNanoSeconds-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 99999,
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
    'ReselectionThresholdQ': {
        'k': 'int',
        'lb': 0,
        'ub': 31,
        'ext': False,
    },
    'SBAS_ID_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'sbas-id-r16',
                {
                    'k': 'enum',
                    'names': ['waas', 'egnos', 'msas', 'gagan'],
                    'ext': [],
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SCS_SpecificCarrier': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'offsetToCarrier',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 2199,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'subcarrierSpacing',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                False,
                None,
            ],
            [
                'carrierBandwidth',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 275,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['txDirectCurrentLocation'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'txDirectCurrentLocation',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 4095,
                                'ext': False,
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
    'SDT_ConfigCommonSIB_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'sdt-RSRP-Threshold-r17',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'sdt-LogicalChannelSR-DelayTimer-r17',
                {
                    'k': 'enum',
                    'names': [
                        'sf20',
                        'sf40',
                        'sf64',
                        'sf128',
                        'sf512',
                        'sf1024',
                        'sf2560',
                        'spare1',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'sdt-DataVolumeThreshold-r17',
                {
                    'k': 'enum',
                    'names': [
                        'byte32',
                        'byte100',
                        'byte200',
                        'byte400',
                        'byte600',
                        'byte800',
                        'byte1000',
                        'byte2000',
                        'byte4000',
                        'byte8000',
                        'byte9000',
                        'byte10000',
                        'byte12000',
                        'byte24000',
                        'byte48000',
                        'byte96000',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't319a-r17',
                {
                    'k': 'enum',
                    'names': [
                        'ms100',
                        'ms200',
                        'ms300',
                        'ms400',
                        'ms600',
                        'ms1000',
                        'ms2000',
                        'ms3000',
                        'ms4000',
                        'spare7',
                        'spare6',
                        'spare5',
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
    'SIB1': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'cellSelectionInfo',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'q-RxLevMin',
                            {
                                'k': 'ref',
                                't': 'Q_RxLevMin',
                            },
                            False,
                            None,
                        ],
                        [
                            'q-RxLevMinOffset',
                            {
                                'k': 'int',
                                'lb': 1,
                                'ub': 8,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'q-RxLevMinSUL',
                            {
                                'k': 'ref',
                                't': 'Q_RxLevMin',
                            },
                            True,
                            None,
                        ],
                        [
                            'q-QualMin',
                            {
                                'k': 'ref',
                                't': 'Q_QualMin',
                            },
                            True,
                            None,
                        ],
                        [
                            'q-QualMinOffset',
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
                True,
                None,
            ],
            [
                'cellAccessRelatedInfo',
                {
                    'k': 'ref',
                    't': 'CellAccessRelatedInfo',
                },
                False,
                None,
            ],
            [
                'connEstFailureControl',
                {
                    'k': 'ref',
                    't': 'ConnEstFailureControl',
                },
                True,
                None,
            ],
            [
                'si-SchedulingInfo',
                {
                    'k': 'ref',
                    't': 'SI_SchedulingInfo',
                },
                True,
                None,
            ],
            [
                'servingCellConfigCommon',
                {
                    'k': 'ref',
                    't': 'ServingCellConfigCommonSIB',
                },
                True,
                None,
            ],
            [
                'ims-EmergencySupport',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'eCallOverIMS-Support',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ue-TimersAndConstants',
                {
                    'k': 'ref',
                    't': 'UE_TimersAndConstants',
                },
                True,
                None,
            ],
            [
                'uac-BarringInfo',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'uac-BarringForCommon',
                            {
                                'k': 'ref',
                                't': 'UAC_BarringPerCatList',
                            },
                            True,
                            None,
                        ],
                        [
                            'uac-BarringPerPLMN-List',
                            {
                                'k': 'ref',
                                't': 'UAC_BarringPerPLMN_List',
                            },
                            True,
                            None,
                        ],
                        [
                            'uac-BarringInfoSetList',
                            {
                                'k': 'ref',
                                't': 'UAC_BarringInfoSetList',
                            },
                            False,
                            None,
                        ],
                        [
                            'uac-AccessCategory1-SelectionAssistanceInfo',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'plmnCommon',
                                        {
                                            'k': 'ref',
                                            't': 'UAC_AccessCategory1_SelectionAssistanceInfo',
                                        },
                                    ],
                                    [
                                        'individualPLMNList',
                                        {
                                            'k': 'seqof',
                                            'size': [2, 12],
                                            'ext': False,
                                            'of': {
                                                'k': 'ref',
                                                't': 'UAC_AccessCategory1_SelectionAssistanceInfo',
                                            },
                                        },
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
                True,
                None,
            ],
            [
                'useFullResumeID',
                {
                    'k': 'enum',
                    'names': ['true'],
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
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SIB1_v1610_IEs',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB10_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'hrnn-List-r16',
                {
                    'k': 'ref',
                    't': 'HRNN_List_r16',
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
    'SIB11_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'measIdleConfigSIB-r16',
                {
                    'k': 'ref',
                    't': 'MeasIdleConfigSIB_r16',
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
    'SIB12_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'segmentNumber-r16',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'segmentType-r16',
                {
                    'k': 'enum',
                    'names': ['notLastSegment', 'lastSegment'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'segmentContainer-r16',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB13_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'sl-V2X-ConfigCommon-r16',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
            [
                'dummy',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
            [
                'tdd-Config-r16',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
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
        'extadd': [],
    },
    'SIB14_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'sl-V2X-ConfigCommonExt-r16',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
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
        'extadd': [],
    },
    'SIB15_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'commonPLMNsWithDisasterCondition-r17',
                {
                    'k': 'seqof',
                    'size': [1, 12],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PLMN_Identity',
                    },
                },
                True,
                None,
            ],
            [
                'applicableDisasterInfoList-r17',
                {
                    'k': 'seqof',
                    'size': [1, 12],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'ApplicableDisasterInfo_r17',
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
        'extadd': [],
    },
    'SIB16_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'freqPriorityListSlicing-r17',
                {
                    'k': 'ref',
                    't': 'FreqPriorityListSlicing_r17',
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
    'SIB17_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'segmentNumber-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'segmentType-r17',
                {
                    'k': 'enum',
                    'names': ['notLastSegment', 'lastSegment'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'segmentContainer-r17',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB17bis_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'segmentNumber-r18',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'segmentType-r18',
                {
                    'k': 'enum',
                    'names': ['notLastSegment', 'lastSegment'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'segmentContainer-r18',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB18_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'gin-ElementList-r17',
                {
                    'k': 'seqof',
                    'size': [1, 24],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'GIN_Element_r17',
                    },
                },
                True,
                None,
            ],
            [
                'gins-PerSNPN-List-r17',
                {
                    'k': 'seqof',
                    'size': [1, 12],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'GINs_PerSNPN_r17',
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
        'extadd': [],
    },
    'SIB19_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'ntn-Config-r17',
                {
                    'k': 'ref',
                    't': 'NTN_Config_r17',
                },
                True,
                None,
            ],
            [
                't-Service-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 549755813887,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'referenceLocation-r17',
                {
                    'k': 'ref',
                    't': 'ReferenceLocation_r17',
                },
                True,
                None,
            ],
            [
                'distanceThresh-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 65525,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'ntn-NeighCellConfigList-r17',
                {
                    'k': 'ref',
                    't': 'NTN_NeighCellConfigList_r17',
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
                'names': ['ntn-NeighCellConfigListExt-v1720'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ntn-NeighCellConfigListExt-v1720',
                            {
                                'k': 'ref',
                                't': 'NTN_NeighCellConfigList_r17',
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
                    'movingReferenceLocation-r18',
                    'ntn-CovEnh-r18',
                    'satSwitchWithReSync-r18',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'movingReferenceLocation-r18',
                            {
                                'k': 'ref',
                                't': 'ReferenceLocation_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'ntn-CovEnh-r18',
                            {
                                'k': 'ref',
                                't': 'NTN_CovEnh_r18',
                            },
                            True,
                            None,
                        ],
                        [
                            'satSwitchWithReSync-r18',
                            {
                                'k': 'ref',
                                't': 'SatSwitchWithReSync_r18',
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
    'SIB1_v1610_IEs': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'idleModeMeasurementsEUTRA-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'idleModeMeasurementsNR-r16',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'posSI-SchedulingInfo-r16',
                {
                    'k': 'ref',
                    't': 'PosSI_SchedulingInfo_r16',
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SIB1_v1630_IEs',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB1_v1630_IEs': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'uac-BarringInfo-v1630',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'uac-AC1-SelectAssistInfo-r16',
                            {
                                'k': 'seqof',
                                'size': [2, 12],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'UAC_AC1_SelectAssistInfo_r16',
                                },
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
                    't': 'SIB1_v1700_IEs',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB1_v1700_IEs': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'hsdn-Cell-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'uac-BarringInfo-v1700',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'uac-BarringInfoSetList-v1700',
                            {
                                'k': 'ref',
                                't': 'UAC_BarringInfoSetList_v1700',
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
                'sdt-ConfigCommon-r17',
                {
                    'k': 'ref',
                    't': 'SDT_ConfigCommonSIB_r17',
                },
                True,
                None,
            ],
            [
                'redCap-ConfigCommon-r17',
                {
                    'k': 'ref',
                    't': 'RedCap_ConfigCommonSIB_r17',
                },
                True,
                None,
            ],
            [
                'featurePriorities-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'redCapPriority-r17',
                            {
                                'k': 'ref',
                                't': 'FeaturePriority_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'slicingPriority-r17',
                            {
                                'k': 'ref',
                                't': 'FeaturePriority_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'msg3-Repetitions-Priority-r17',
                            {
                                'k': 'ref',
                                't': 'FeaturePriority_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'sdt-Priority-r17',
                            {
                                'k': 'ref',
                                't': 'FeaturePriority_r17',
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
                'si-SchedulingInfo-v1700',
                {
                    'k': 'ref',
                    't': 'SI_SchedulingInfo_v1700',
                },
                True,
                None,
            ],
            [
                'hyperSFN-r17',
                {
                    'k': 'bits',
                    'size': [10, 10],
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'eDRX-AllowedIdle-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'eDRX-AllowedInactive-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'intraFreqReselectionRedCap-r17',
                {
                    'k': 'enum',
                    'names': ['allowed', 'notAllowed'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'cellBarredNTN-r17',
                {
                    'k': 'enum',
                    'names': ['barred', 'notBarred'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SIB1_v1740_IEs',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB1_v1740_IEs': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'si-SchedulingInfo-v1740',
                {
                    'k': 'ref',
                    't': 'SI_SchedulingInfo_v1740',
                },
                True,
                None,
            ],
            [
                'nonCriticalExtension',
                {
                    'k': 'ref',
                    't': 'SIB1_v1800_IEs',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB1_v1800_IEs': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ncr-Support-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'mt-SDT-ConfigCommonSIB-r18',
                {
                    'k': 'ref',
                    't': 'MT_SDT_ConfigCommonSIB_r18',
                },
                True,
                None,
            ],
            [
                'musim-CapRestrictionAllowed-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'featurePriorities-v1800',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'msg1-Repetitions-Priority-r18',
                            {
                                'k': 'ref',
                                't': 'FeaturePriority_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'eRedCapPriority-r18',
                            {
                                'k': 'ref',
                                't': 'FeaturePriority_r17',
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
                'si-SchedulingInfo-v1800',
                {
                    'k': 'ref',
                    't': 'SI_SchedulingInfo_v1800',
                },
                True,
                None,
            ],
            [
                'cellBarredATG-r18',
                {
                    'k': 'enum',
                    'names': ['barred', 'notBarred'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'cellBarredNES-r18',
                {
                    'k': 'enum',
                    'names': ['notBarred'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'mobileIAB-Cell-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'eDRX-AllowedInactive-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'intraFreqReselection-eRedCap-r18',
                {
                    'k': 'enum',
                    'names': ['allowed', 'notAllowed'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'nonServingCellMII-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'sdt-BeamFailureRecoveryProhibitTimer-r18',
                {
                    'k': 'enum',
                    'names': [
                        'ms50',
                        'ms100',
                        'ms200',
                        'ms500',
                        'ms1000',
                        'ms1500',
                        'ms2000',
                        'ms3000',
                    ],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'eRedCap-ConfigCommon-r18',
                {
                    'k': 'ref',
                    't': 'ERedCap_ConfigCommonSIB_r18',
                },
                True,
                None,
            ],
            [
                'cellBarredFixedVSAT-r18',
                {
                    'k': 'enum',
                    'names': ['barred', 'notBarred'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'cellBarredMobileVSAT-r18',
                {
                    'k': 'enum',
                    'names': ['barred', 'notBarred'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'reselectionMeasurementsNR-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'cellBarred2RxXR-r18',
                {
                    'k': 'enum',
                    'names': ['barred'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'intraFreqReselection2RxXR-r18',
                {
                    'k': 'enum',
                    'names': ['allowed', 'notAllowed'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'barringExemptEmergencyCall-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'n3c-Support-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
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
    'SIB2': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'cellReselectionInfoCommon',
                {
                    'k': 'seq',
                    'ext': True,
                    'comp': [
                        [
                            'nrofSS-BlocksToAverage',
                            {
                                'k': 'int',
                                'lb': 2,
                                'ub': 16,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'absThreshSS-BlocksConsolidation',
                            {
                                'k': 'ref',
                                't': 'ThresholdNR',
                            },
                            True,
                            None,
                        ],
                        [
                            'rangeToBestCell',
                            {
                                'k': 'ref',
                                't': 'RangeToBestCell',
                            },
                            True,
                            None,
                        ],
                        [
                            'q-Hyst',
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
                        [
                            'speedStateReselectionPars',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'mobilityStateParameters',
                                        {
                                            'k': 'ref',
                                            't': 'MobilityStateParameters',
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'q-HystSF',
                                        {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    'sf-Medium',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['dB-6', 'dB-4', 'dB-2', 'dB0'],
                                                        'ext': None,
                                                    },
                                                    False,
                                                    None,
                                                ],
                                                [
                                                    'sf-High',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['dB-6', 'dB-4', 'dB-2', 'dB0'],
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
                                ],
                                'extadd': [],
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
                'cellReselectionServingFreqInfo',
                {
                    'k': 'seq',
                    'ext': True,
                    'comp': [
                        [
                            's-NonIntraSearchP',
                            {
                                'k': 'ref',
                                't': 'ReselectionThreshold',
                            },
                            True,
                            None,
                        ],
                        [
                            's-NonIntraSearchQ',
                            {
                                'k': 'ref',
                                't': 'ReselectionThresholdQ',
                            },
                            True,
                            None,
                        ],
                        [
                            'threshServingLowP',
                            {
                                'k': 'ref',
                                't': 'ReselectionThreshold',
                            },
                            False,
                            None,
                        ],
                        [
                            'threshServingLowQ',
                            {
                                'k': 'ref',
                                't': 'ReselectionThresholdQ',
                            },
                            True,
                            None,
                        ],
                        [
                            'cellReselectionPriority',
                            {
                                'k': 'ref',
                                't': 'CellReselectionPriority',
                            },
                            False,
                            None,
                        ],
                        [
                            'cellReselectionSubPriority',
                            {
                                'k': 'ref',
                                't': 'CellReselectionSubPriority',
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
                'intraFreqCellReselectionInfo',
                {
                    'k': 'seq',
                    'ext': True,
                    'comp': [
                        [
                            'q-RxLevMin',
                            {
                                'k': 'ref',
                                't': 'Q_RxLevMin',
                            },
                            False,
                            None,
                        ],
                        [
                            'q-RxLevMinSUL',
                            {
                                'k': 'ref',
                                't': 'Q_RxLevMin',
                            },
                            True,
                            None,
                        ],
                        [
                            'q-QualMin',
                            {
                                'k': 'ref',
                                't': 'Q_QualMin',
                            },
                            True,
                            None,
                        ],
                        [
                            's-IntraSearchP',
                            {
                                'k': 'ref',
                                't': 'ReselectionThreshold',
                            },
                            False,
                            None,
                        ],
                        [
                            's-IntraSearchQ',
                            {
                                'k': 'ref',
                                't': 'ReselectionThresholdQ',
                            },
                            True,
                            None,
                        ],
                        [
                            't-ReselectionNR',
                            {
                                'k': 'ref',
                                't': 'T_Reselection',
                            },
                            False,
                            None,
                        ],
                        [
                            'frequencyBandList',
                            {
                                'k': 'ref',
                                't': 'MultiFrequencyBandListNR_SIB',
                            },
                            True,
                            None,
                        ],
                        [
                            'frequencyBandListSUL',
                            {
                                'k': 'ref',
                                't': 'MultiFrequencyBandListNR_SIB',
                            },
                            True,
                            None,
                        ],
                        [
                            'p-Max',
                            {
                                'k': 'ref',
                                't': 'P_Max',
                            },
                            True,
                            None,
                        ],
                        [
                            'smtc',
                            {
                                'k': 'ref',
                                't': 'SSB_MTC',
                            },
                            True,
                            None,
                        ],
                        [
                            'ss-RSSI-Measurement',
                            {
                                'k': 'ref',
                                't': 'SS_RSSI_Measurement',
                            },
                            True,
                            None,
                        ],
                        [
                            'ssb-ToMeasure',
                            {
                                'k': 'ref',
                                't': 'SSB_ToMeasure',
                            },
                            True,
                            None,
                        ],
                        [
                            'deriveSSB-IndexFromCell',
                            {
                                'k': 'bool',
                            },
                            False,
                            None,
                        ],
                    ],
                    'extadd': [
                        {
                            'k': 'extgrp',
                            'names': ['t-ReselectionNR-SF'],
                            'node': {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        't-ReselectionNR-SF',
                                        {
                                            'k': 'ref',
                                            't': 'SpeedStateScaleFactors',
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
                            'names': ['smtc2-LP-r16', 'ssb-PositionQCL-Common-r16'],
                            'node': {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'smtc2-LP-r16',
                                        {
                                            'k': 'ref',
                                            't': 'SSB_MTC2_LP_r16',
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'ssb-PositionQCL-Common-r16',
                                        {
                                            'k': 'ref',
                                            't': 'SSB_PositionQCL_Relation_r16',
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
                            'names': ['ssb-PositionQCL-Common-r17'],
                            'node': {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'ssb-PositionQCL-Common-r17',
                                        {
                                            'k': 'ref',
                                            't': 'SSB_PositionQCL_Relation_r17',
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
                            'names': ['smtc4list-r17'],
                            'node': {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'smtc4list-r17',
                                        {
                                            'k': 'ref',
                                            't': 'SSB_MTC4List_r17',
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
                            'names': ['frequencyBandList-v1760', 'frequencyBandListSUL-v1760'],
                            'node': {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'frequencyBandList-v1760',
                                        {
                                            'k': 'ref',
                                            't': 'MultiFrequencyBandListNR_SIB_v1760',
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'frequencyBandListSUL-v1760',
                                        {
                                            'k': 'ref',
                                            't': 'MultiFrequencyBandListNR_SIB_v1760',
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
                            'names': ['frequencyBandListAerial-r18'],
                            'node': {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'frequencyBandListAerial-r18',
                                        {
                                            'k': 'ref',
                                            't': 'MultiFrequencyBandListNR_Aerial_SIB_r18',
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
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['relaxedMeasurement-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'relaxedMeasurement-r16',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'lowMobilityEvaluation-r16',
                                        {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    's-SearchDeltaP-r16',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['dB3', 'dB6', 'dB9', 'dB12', 'dB15', 'spare3', 'spare2', 'spare1'],
                                                        'ext': None,
                                                    },
                                                    False,
                                                    None,
                                                ],
                                                [
                                                    't-SearchDeltaP-r16',
                                                    {
                                                        'k': 'enum',
                                                        'names': [
                                                            's5',
                                                            's10',
                                                            's20',
                                                            's30',
                                                            's60',
                                                            's120',
                                                            's180',
                                                            's240',
                                                            's300',
                                                            'spare7',
                                                            'spare6',
                                                            'spare5',
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
                                        True,
                                        None,
                                    ],
                                    [
                                        'cellEdgeEvaluation-r16',
                                        {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    's-SearchThresholdP-r16',
                                                    {
                                                        'k': 'ref',
                                                        't': 'ReselectionThreshold',
                                                    },
                                                    False,
                                                    None,
                                                ],
                                                [
                                                    's-SearchThresholdQ-r16',
                                                    {
                                                        'k': 'ref',
                                                        't': 'ReselectionThresholdQ',
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
                                        'combineRelaxedMeasCondition-r16',
                                        {
                                            'k': 'enum',
                                            'names': ['true'],
                                            'ext': None,
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'highPriorityMeasRelax-r16',
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
                    ],
                    'extadd': [],
                },
            },
            {
                'k': 'extgrp',
                'names': ['cellEquivalentSize-r17', 'relaxedMeasurement-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'cellEquivalentSize-r17',
                            {
                                'k': 'int',
                                'lb': 2,
                                'ub': 16,
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'relaxedMeasurement-r17',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'stationaryMobilityEvaluation-r17',
                                        {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    's-SearchDeltaP-Stationary-r17',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['dB2', 'dB3', 'dB6', 'dB9', 'dB12', 'dB15', 'spare2', 'spare1'],
                                                        'ext': None,
                                                    },
                                                    False,
                                                    None,
                                                ],
                                                [
                                                    't-SearchDeltaP-Stationary-r17',
                                                    {
                                                        'k': 'enum',
                                                        'names': [
                                                            's5',
                                                            's10',
                                                            's20',
                                                            's30',
                                                            's60',
                                                            's120',
                                                            's180',
                                                            's240',
                                                            's300',
                                                            'spare7',
                                                            'spare6',
                                                            'spare5',
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
                                        False,
                                        None,
                                    ],
                                    [
                                        'cellEdgeEvaluationWhileStationary-r17',
                                        {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    's-SearchThresholdP2-r17',
                                                    {
                                                        'k': 'ref',
                                                        't': 'ReselectionThreshold',
                                                    },
                                                    False,
                                                    None,
                                                ],
                                                [
                                                    's-SearchThresholdQ2-r17',
                                                    {
                                                        'k': 'ref',
                                                        't': 'ReselectionThresholdQ',
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
                                        'combineRelaxedMeasCondition2-r17',
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
                    ],
                    'extadd': [],
                },
            },
        ],
    },
    'SIB20_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'mcch-Config-r17',
                {
                    'k': 'ref',
                    't': 'MCCH_Config_r17',
                },
                False,
                None,
            ],
            [
                'cfr-ConfigMCCH-MTCH-r17',
                {
                    'k': 'ref',
                    't': 'CFR_ConfigMCCH_MTCH_r17',
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
                'names': ['cfr-ConfigMCCH-MTCH-RedCap-r18', 'mcch-ConfigRedCap-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'cfr-ConfigMCCH-MTCH-RedCap-r18',
                            {
                                'k': 'ref',
                                't': 'CFR_ConfigMCCH_MTCH_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'mcch-ConfigRedCap-r18',
                            {
                                'k': 'ref',
                                't': 'MCCH_Config_r17',
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
    'SIB21_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'mbs-FSAI-IntraFreq-r17',
                {
                    'k': 'ref',
                    't': 'MBS_FSAI_List_r17',
                },
                True,
                None,
            ],
            [
                'mbs-FSAI-InterFreqList-r17',
                {
                    'k': 'ref',
                    't': 'MBS_FSAI_InterFreqList_r17',
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
    'SIB22_r18': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'atg-Config-r18',
                {
                    'k': 'ref',
                    't': 'ATG_Config_r18',
                },
                True,
                None,
            ],
            [
                'hs-ATG-CellReselectionSet-r18',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'atg-NeighCellConfigList-r18',
                {
                    'k': 'ref',
                    't': 'ATG_NeighCellConfigList_r18',
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
    'SIB23_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'segmentNumber-r18',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'segmentType-r18',
                {
                    'k': 'enum',
                    'names': ['notLastSegment', 'lastSegment'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'segmentContainer-r18',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SIB24_r18': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'multicastMCCH-Config-r18',
                {
                    'k': 'ref',
                    't': 'MCCH_Config_r17',
                },
                True,
                None,
            ],
            [
                'cfr-ConfigMCCH-MTCH-r18',
                {
                    'k': 'ref',
                    't': 'CFR_ConfigMCCH_MTCH_r17',
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
    'SIB25_r18': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'coverageAreaInfoList-r18',
                {
                    'k': 'ref',
                    't': 'CoverageAreaInfoList_r18',
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
    'SIB3': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'intraFreqNeighCellList',
                {
                    'k': 'ref',
                    't': 'IntraFreqNeighCellList',
                },
                True,
                None,
            ],
            [
                'intraFreqExcludedCellList',
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
                'names': [
                    'intraFreqNeighCellList-v1610',
                    'intraFreqAllowedCellList-r16',
                    'intraFreqCAG-CellList-r16',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'intraFreqNeighCellList-v1610',
                            {
                                'k': 'ref',
                                't': 'IntraFreqNeighCellList_v1610',
                            },
                            True,
                            None,
                        ],
                        [
                            'intraFreqAllowedCellList-r16',
                            {
                                'k': 'ref',
                                't': 'IntraFreqAllowedCellList_r16',
                            },
                            True,
                            None,
                        ],
                        [
                            'intraFreqCAG-CellList-r16',
                            {
                                'k': 'seqof',
                                'size': [1, 12],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'IntraFreqCAG_CellListPerPLMN_r16',
                                },
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
                'names': ['intraFreqNeighHSDN-CellList-r17', 'intraFreqNeighCellList-v1710'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'intraFreqNeighHSDN-CellList-r17',
                            {
                                'k': 'ref',
                                't': 'IntraFreqNeighHSDN_CellList_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'intraFreqNeighCellList-v1710',
                            {
                                'k': 'ref',
                                't': 'IntraFreqNeighCellList_v1710',
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
                'names': ['channelAccessMode2-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'channelAccessMode2-r17',
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
        ],
    },
    'SIB4': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'interFreqCarrierFreqList',
                {
                    'k': 'ref',
                    't': 'InterFreqCarrierFreqList',
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
                'names': ['interFreqCarrierFreqList-v1610'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'interFreqCarrierFreqList-v1610',
                            {
                                'k': 'ref',
                                't': 'InterFreqCarrierFreqList_v1610',
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
                'names': ['interFreqCarrierFreqList-v1700'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'interFreqCarrierFreqList-v1700',
                            {
                                'k': 'ref',
                                't': 'InterFreqCarrierFreqList_v1700',
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
                'names': ['interFreqCarrierFreqList-v1720'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'interFreqCarrierFreqList-v1720',
                            {
                                'k': 'ref',
                                't': 'InterFreqCarrierFreqList_v1720',
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
                'names': ['interFreqCarrierFreqList-v1730'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'interFreqCarrierFreqList-v1730',
                            {
                                'k': 'ref',
                                't': 'InterFreqCarrierFreqList_v1730',
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
                'names': ['interFreqCarrierFreqList-v1760'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'interFreqCarrierFreqList-v1760',
                            {
                                'k': 'ref',
                                't': 'InterFreqCarrierFreqList_v1760',
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
                'names': ['interFreqCarrierFreqList-v1800'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'interFreqCarrierFreqList-v1800',
                            {
                                'k': 'ref',
                                't': 'InterFreqCarrierFreqList_v1800',
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
    'SIB5': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'carrierFreqListEUTRA',
                {
                    'k': 'ref',
                    't': 'CarrierFreqListEUTRA',
                },
                True,
                None,
            ],
            [
                't-ReselectionEUTRA',
                {
                    'k': 'ref',
                    't': 'T_Reselection',
                },
                False,
                None,
            ],
            [
                't-ReselectionEUTRA-SF',
                {
                    'k': 'ref',
                    't': 'SpeedStateScaleFactors',
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
                'names': ['carrierFreqListEUTRA-v1610'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'carrierFreqListEUTRA-v1610',
                            {
                                'k': 'ref',
                                't': 'CarrierFreqListEUTRA_v1610',
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
                'names': ['carrierFreqListEUTRA-v1700', 'idleModeMeasVoiceFallback-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'carrierFreqListEUTRA-v1700',
                            {
                                'k': 'ref',
                                't': 'CarrierFreqListEUTRA_v1700',
                            },
                            True,
                            None,
                        ],
                        [
                            'idleModeMeasVoiceFallback-r17',
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
                'names': ['carrierFreqListEUTRA-v1800'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'carrierFreqListEUTRA-v1800',
                            {
                                'k': 'ref',
                                't': 'CarrierFreqListEUTRA_v1800',
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
    'SIB6': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'messageIdentifier',
                {
                    'k': 'bits',
                    'size': [16, 16],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'serialNumber',
                {
                    'k': 'bits',
                    'size': [16, 16],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'warningType',
                {
                    'k': 'octets',
                    'size': [2, 2],
                    'ext': False,
                    'containing': None,
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
        'extadd': [],
    },
    'SIB7': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'messageIdentifier',
                {
                    'k': 'bits',
                    'size': [16, 16],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'serialNumber',
                {
                    'k': 'bits',
                    'size': [16, 16],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'warningMessageSegmentType',
                {
                    'k': 'enum',
                    'names': ['notLastSegment', 'lastSegment'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'warningMessageSegmentNumber',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'warningMessageSegment',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
            [
                'dataCodingScheme',
                {
                    'k': 'octets',
                    'size': [1, 1],
                    'ext': False,
                    'containing': None,
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
    'SIB8': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'messageIdentifier',
                {
                    'k': 'bits',
                    'size': [16, 16],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'serialNumber',
                {
                    'k': 'bits',
                    'size': [16, 16],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'warningMessageSegmentType',
                {
                    'k': 'enum',
                    'names': ['notLastSegment', 'lastSegment'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'warningMessageSegmentNumber',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'warningMessageSegment',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
            [
                'dataCodingScheme',
                {
                    'k': 'octets',
                    'size': [1, 1],
                    'ext': False,
                    'containing': None,
                },
                True,
                None,
            ],
            [
                'warningAreaCoordinatesSegment',
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
    'SIB9': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'timeInfo',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'timeInfoUTC',
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
                            'dayLightSavingTime',
                            {
                                'k': 'bits',
                                'size': [2, 2],
                                'ext': False,
                            },
                            True,
                            None,
                        ],
                        [
                            'leapSeconds',
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
                            'localTimeOffset',
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
                'names': ['referenceTimeInfo-r16'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'referenceTimeInfo-r16',
                            {
                                'k': 'ref',
                                't': 'ReferenceTimeInfo_r16',
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
                'names': ['eventID-TSS-r18'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'eventID-TSS-r18',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 63,
                                'ext': False,
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
    'SIB_Mapping': {
        'k': 'seqof',
        'size': [1, 32],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SIB_TypeInfo',
        },
    },
    'SIB_Mapping_v1700': {
        'k': 'seqof',
        'size': [1, 32],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SIB_TypeInfo_v1700',
        },
    },
    'SIB_TypeInfo': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'type',
                {
                    'k': 'enum',
                    'names': [
                        'sibType2',
                        'sibType3',
                        'sibType4',
                        'sibType5',
                        'sibType6',
                        'sibType7',
                        'sibType8',
                        'sibType9',
                        'sibType10-v1610',
                        'sibType11-v1610',
                        'sibType12-v1610',
                        'sibType13-v1610',
                        'sibType14-v1610',
                        'spare3',
                        'spare2',
                        'spare1',
                    ],
                    'ext': [],
                },
                False,
                None,
            ],
            [
                'valueTag',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 31,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'areaScope',
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
    'SIB_TypeInfo_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'sibType-r17',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'type1-r17',
                            {
                                'k': 'enum',
                                'names': [
                                    'sibType15',
                                    'sibType16',
                                    'sibType17',
                                    'sibType18',
                                    'sibType19',
                                    'sibType20',
                                    'sibType21',
                                    'sibType22-v1800',
                                    'sibType23-v1800',
                                    'sibType24-v1800',
                                    'sibType25-v1800',
                                    'sibType17bis-v1820',
                                    'spare4',
                                    'spare3',
                                    'spare2',
                                    'spare1',
                                ],
                                'ext': [],
                            },
                        ],
                        [
                            'type2-r17',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'posSibType-r17',
                                        {
                                            'k': 'enum',
                                            'names': [
                                                'posSibType1-9',
                                                'posSibType1-10',
                                                'posSibType2-24',
                                                'posSibType2-25',
                                                'posSibType6-4',
                                                'posSibType6-5',
                                                'posSibType6-6',
                                                'posSibType2-17a-v1770',
                                                'posSibType2-18a-v1770',
                                                'posSibType2-20a-v1770',
                                                'posSibType1-11-v1800',
                                                'posSibType1-12-v1800',
                                                'posSibType2-26-v1800',
                                                'posSibType2-27-v1800',
                                                'posSibType6-7-v1800',
                                                'posSibType7-1-v1800',
                                            ],
                                            'ext': ['posSibType7-2-v1800', 'posSibType7-3-v1800', 'posSibType7-4-v1800'],
                                        },
                                        False,
                                        None,
                                    ],
                                    [
                                        'encrypted-r17',
                                        {
                                            'k': 'enum',
                                            'names': ['true'],
                                            'ext': None,
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'gnss-id-r17',
                                        {
                                            'k': 'ref',
                                            't': 'GNSS_ID_r16',
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'sbas-id-r17',
                                        {
                                            'k': 'ref',
                                            't': 'SBAS_ID_r16',
                                        },
                                        True,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                        ],
                    ],
                    'extadd': [],
                },
                False,
                None,
            ],
            [
                'valueTag-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 31,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'areaScope-r17',
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
    'SIBpos_r16': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'assistanceDataSIB-Element-r16',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
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
        'extadd': [],
    },
    'SINR_Range': {
        'k': 'int',
        'lb': 0,
        'ub': 127,
        'ext': False,
    },
    'SI_RequestConfig': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'rach-OccasionsSI',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'rach-ConfigSI',
                            {
                                'k': 'ref',
                                't': 'RACH_ConfigGeneric',
                            },
                            False,
                            None,
                        ],
                        [
                            'ssb-perRACH-Occasion',
                            {
                                'k': 'enum',
                                'names': [
                                    'oneEighth',
                                    'oneFourth',
                                    'oneHalf',
                                    'one',
                                    'two',
                                    'four',
                                    'eight',
                                    'sixteen',
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
            [
                'si-RequestPeriod',
                {
                    'k': 'enum',
                    'names': ['one', 'two', 'four', 'six', 'eight', 'ten', 'twelve', 'sixteen'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'si-RequestResources',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SI_RequestResources',
                    },
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SI_RequestConfigRepetition_r18': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'rach-OccasionsSI-r18',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'rach-ConfigSI-r18',
                            {
                                'k': 'ref',
                                't': 'RACH_ConfigGeneric',
                            },
                            False,
                            None,
                        ],
                        [
                            'ssb-perRACH-Occasion-r18',
                            {
                                'k': 'enum',
                                'names': [
                                    'oneEighth',
                                    'oneFourth',
                                    'oneHalf',
                                    'one',
                                    'two',
                                    'four',
                                    'eight',
                                    'sixteen',
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
            [
                'si-RequestResourcesRepetitionNum2-r18',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SI_RequestResourcesRepetition_r18',
                    },
                },
                True,
                None,
            ],
            [
                'si-RequestResourcesRepetitionNum4-r18',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SI_RequestResourcesRepetition_r18',
                    },
                },
                True,
                None,
            ],
            [
                'si-RequestResourcesRepetitionNum8-r18',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SI_RequestResourcesRepetition_r18',
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SI_RequestResources': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ra-PreambleStartIndex',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'ra-AssociationPeriodIndex',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 15,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'ra-ssb-OccasionMaskIndex',
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
        'extadd': [],
    },
    'SI_RequestResourcesRepetition_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ra-PreambleStartIndex-r18',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 63,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SI_SchedulingInfo': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'schedulingInfoList',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SchedulingInfo',
                    },
                },
                False,
                None,
            ],
            [
                'si-WindowLength',
                {
                    'k': 'enum',
                    'names': [
                        's5',
                        's10',
                        's20',
                        's40',
                        's80',
                        's160',
                        's320',
                        's640',
                        's1280',
                        's2560-v1710',
                        's5120-v1710',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'si-RequestConfig',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfig',
                },
                True,
                None,
            ],
            [
                'si-RequestConfigSUL',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfig',
                },
                True,
                None,
            ],
            [
                'systemInformationAreaID',
                {
                    'k': 'bits',
                    'size': [24, 24],
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SI_SchedulingInfo_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'schedulingInfoList2-r17',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'SchedulingInfo2_r17',
                    },
                },
                False,
                None,
            ],
            [
                'dummy',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfig',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SI_SchedulingInfo_v1740': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'si-RequestConfigRedCap-r17',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfig',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SI_SchedulingInfo_v1800': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'si-RequestConfigMSG1-Repetition-r18',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfigRepetition_r18',
                },
                True,
                None,
            ],
            [
                'si-RequestConfigRedCap-MSG1-Repetition-r18',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfigRepetition_r18',
                },
                True,
                None,
            ],
            [
                'si-RequestConfigSUL-MSG1-Repetition-r18',
                {
                    'k': 'ref',
                    't': 'SI_RequestConfigRepetition_r18',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SNPN_AccessInfo_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'extCH-Supported-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'extCH-WithoutConfigAllowed-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'onboardingEnabled-r17',
                {
                    'k': 'enum',
                    'names': ['true'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'imsEmergencySupportForSNPN-r17',
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
    'SSB_MTC': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'periodicityAndOffset',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'sf5',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 4,
                                'ext': False,
                            },
                        ],
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
                            'sf40',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 39,
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
                            'sf160',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 159,
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
                'duration',
                {
                    'k': 'enum',
                    'names': ['sf1', 'sf2', 'sf3', 'sf4', 'sf5'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SSB_MTC2_LP_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'pci-List',
                {
                    'k': 'seqof',
                    'size': [1, 64],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PhysCellId',
                    },
                },
                True,
                None,
            ],
            [
                'periodicity',
                {
                    'k': 'enum',
                    'names': ['sf10', 'sf20', 'sf40', 'sf80', 'sf160', 'spare3', 'spare2', 'spare1'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SSB_MTC4List_r17': {
        'k': 'seqof',
        'size': [1, 3],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SSB_MTC4_r17',
        },
    },
    'SSB_MTC4_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'pci-List-r17',
                {
                    'k': 'seqof',
                    'size': [1, 64],
                    'ext': False,
                    'of': {
                        'k': 'ref',
                        't': 'PhysCellId',
                    },
                },
                True,
                None,
            ],
            [
                'offset-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 159,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SSB_PositionQCL_Relation_r16': {
        'k': 'enum',
        'names': ['n1', 'n2', 'n4', 'n8'],
        'ext': None,
    },
    'SSB_PositionQCL_Relation_r17': {
        'k': 'enum',
        'names': ['n32', 'n64'],
        'ext': None,
    },
    'SSB_ToMeasure': {
        'k': 'choice',
        'ext': False,
        'alts': [
            [
                'shortBitmap',
                {
                    'k': 'bits',
                    'size': [4, 4],
                    'ext': False,
                },
            ],
            [
                'mediumBitmap',
                {
                    'k': 'bits',
                    'size': [8, 8],
                    'ext': False,
                },
            ],
            [
                'longBitmap',
                {
                    'k': 'bits',
                    'size': [64, 64],
                    'ext': False,
                },
            ],
        ],
        'extadd': [],
    },
    'SS_RSSI_Measurement': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'measurementSlots',
                {
                    'k': 'bits',
                    'size': [1, 80],
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'endSymbol',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 3,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SatSwitchWithReSync_r18': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ntn-Config-r18',
                {
                    'k': 'ref',
                    't': 'NTN_Config_r17',
                },
                False,
                None,
            ],
            [
                't-ServiceStart-r18',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 549755813887,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'ssb-TimeOffset-r18',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 159,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SchedulingInfo': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'si-BroadcastStatus',
                {
                    'k': 'enum',
                    'names': ['broadcasting', 'notBroadcasting'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'si-Periodicity',
                {
                    'k': 'enum',
                    'names': ['rf8', 'rf16', 'rf32', 'rf64', 'rf128', 'rf256', 'rf512'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'sib-MappingInfo',
                {
                    'k': 'ref',
                    't': 'SIB_Mapping',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SchedulingInfo2_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'si-BroadcastStatus-r17',
                {
                    'k': 'enum',
                    'names': ['broadcasting', 'notBroadcasting'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'si-WindowPosition-r17',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 256,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'si-Periodicity-r17',
                {
                    'k': 'enum',
                    'names': ['rf8', 'rf16', 'rf32', 'rf64', 'rf128', 'rf256', 'rf512'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'sib-MappingInfo-r17',
                {
                    'k': 'ref',
                    't': 'SIB_Mapping_v1700',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SearchSpace': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'searchSpaceId',
                {
                    'k': 'ref',
                    't': 'SearchSpaceId',
                },
                False,
                None,
            ],
            [
                'controlResourceSetId',
                {
                    'k': 'ref',
                    't': 'ControlResourceSetId',
                },
                True,
                None,
            ],
            [
                'monitoringSlotPeriodicityAndOffset',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'sl1',
                            {
                                'k': 'null',
                            },
                        ],
                        [
                            'sl2',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1,
                                'ext': False,
                            },
                        ],
                        [
                            'sl4',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 3,
                                'ext': False,
                            },
                        ],
                        [
                            'sl5',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 4,
                                'ext': False,
                            },
                        ],
                        [
                            'sl8',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 7,
                                'ext': False,
                            },
                        ],
                        [
                            'sl10',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 9,
                                'ext': False,
                            },
                        ],
                        [
                            'sl16',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 15,
                                'ext': False,
                            },
                        ],
                        [
                            'sl20',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 19,
                                'ext': False,
                            },
                        ],
                        [
                            'sl40',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 39,
                                'ext': False,
                            },
                        ],
                        [
                            'sl80',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 79,
                                'ext': False,
                            },
                        ],
                        [
                            'sl160',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 159,
                                'ext': False,
                            },
                        ],
                        [
                            'sl320',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 319,
                                'ext': False,
                            },
                        ],
                        [
                            'sl640',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 639,
                                'ext': False,
                            },
                        ],
                        [
                            'sl1280',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 1279,
                                'ext': False,
                            },
                        ],
                        [
                            'sl2560',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 2559,
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'duration',
                {
                    'k': 'int',
                    'lb': 2,
                    'ub': 2559,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'monitoringSymbolsWithinSlot',
                {
                    'k': 'bits',
                    'size': [14, 14],
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'nrofCandidates',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'aggregationLevel1',
                            {
                                'k': 'enum',
                                'names': ['n0', 'n1', 'n2', 'n3', 'n4', 'n5', 'n6', 'n8'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'aggregationLevel2',
                            {
                                'k': 'enum',
                                'names': ['n0', 'n1', 'n2', 'n3', 'n4', 'n5', 'n6', 'n8'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'aggregationLevel4',
                            {
                                'k': 'enum',
                                'names': ['n0', 'n1', 'n2', 'n3', 'n4', 'n5', 'n6', 'n8'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'aggregationLevel8',
                            {
                                'k': 'enum',
                                'names': ['n0', 'n1', 'n2', 'n3', 'n4', 'n5', 'n6', 'n8'],
                                'ext': None,
                            },
                            False,
                            None,
                        ],
                        [
                            'aggregationLevel16',
                            {
                                'k': 'enum',
                                'names': ['n0', 'n1', 'n2', 'n3', 'n4', 'n5', 'n6', 'n8'],
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
                'searchSpaceType',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'common',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'dci-Format0-0-AndFormat1-0',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format2-0',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [
                                                [
                                                    'nrofCandidates-SFI',
                                                    {
                                                        'k': 'seq',
                                                        'ext': False,
                                                        'comp': [
                                                            [
                                                                'aggregationLevel1',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel2',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel4',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel8',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
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
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format2-1',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format2-2',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format2-3',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [
                                                [
                                                    'dummy1',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['sl1', 'sl2', 'sl4', 'sl5', 'sl8', 'sl10', 'sl16', 'sl20'],
                                                        'ext': None,
                                                    },
                                                    True,
                                                    None,
                                                ],
                                                [
                                                    'dummy2',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['n1', 'n2'],
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
                        ],
                        [
                            'ue-Specific',
                            {
                                'k': 'seq',
                                'ext': True,
                                'comp': [
                                    [
                                        'dci-Formats',
                                        {
                                            'k': 'enum',
                                            'names': ['formats0-0-And-1-0', 'formats0-1-And-1-1'],
                                            'ext': None,
                                        },
                                        False,
                                        None,
                                    ],
                                ],
                                'extadd': [
                                    {
                                        'k': 'extgrp',
                                        'names': ['dci-Formats-MT-r16', 'dci-FormatsSL-r16', 'dci-FormatsExt-r16'],
                                        'node': {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    'dci-Formats-MT-r16',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['formats2-5'],
                                                        'ext': None,
                                                    },
                                                    True,
                                                    None,
                                                ],
                                                [
                                                    'dci-FormatsSL-r16',
                                                    {
                                                        'k': 'enum',
                                                        'names': [
                                                            'formats0-0-And-1-0',
                                                            'formats0-1-And-1-1',
                                                            'formats3-0',
                                                            'formats3-1',
                                                            'formats3-0-And-3-1',
                                                        ],
                                                        'ext': None,
                                                    },
                                                    True,
                                                    None,
                                                ],
                                                [
                                                    'dci-FormatsExt-r16',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['formats0-2-And-1-2', 'formats0-1-And-1-1And-0-2-And-1-2'],
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
                                        'names': ['dci-FormatsNCR-r18', 'dci-FormatsSL-PRS-r18'],
                                        'node': {
                                            'k': 'seq',
                                            'ext': False,
                                            'comp': [
                                                [
                                                    'dci-FormatsNCR-r18',
                                                    {
                                                        'k': 'enum',
                                                        'names': ['formats2-8'],
                                                        'ext': None,
                                                    },
                                                    True,
                                                    None,
                                                ],
                                                [
                                                    'dci-FormatsSL-PRS-r18',
                                                    {
                                                        'k': 'enum',
                                                        'names': [
                                                            'formats3-2',
                                                            'formats3-0-And-3-2',
                                                            'formats3-0-And-3-1-And-3-2',
                                                            'formats3-1-And-3-2',
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
    'SearchSpaceExt_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'controlResourceSetId-r16',
                {
                    'k': 'ref',
                    't': 'ControlResourceSetId_r16',
                },
                True,
                None,
            ],
            [
                'searchSpaceType-r16',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'common-r16',
                            {
                                'k': 'seq',
                                'ext': True,
                                'comp': [
                                    [
                                        'dci-Format2-4-r16',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [
                                                [
                                                    'nrofCandidates-CI-r16',
                                                    {
                                                        'k': 'seq',
                                                        'ext': False,
                                                        'comp': [
                                                            [
                                                                'aggregationLevel1-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel2-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel4-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel8-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel16-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
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
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format2-5-r16',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [
                                                [
                                                    'nrofCandidates-IAB-r16',
                                                    {
                                                        'k': 'seq',
                                                        'ext': False,
                                                        'comp': [
                                                            [
                                                                'aggregationLevel1-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel2-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel4-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel8-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel16-r16',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n1', 'n2'],
                                                                    'ext': None,
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
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format2-6-r16',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
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
                True,
                None,
            ],
            [
                'searchSpaceGroupIdList-r16',
                {
                    'k': 'seqof',
                    'size': [1, 2],
                    'ext': False,
                    'of': {
                        'k': 'int',
                        'lb': 0,
                        'ub': 1,
                        'ext': False,
                    },
                },
                True,
                None,
            ],
            [
                'freqMonitorLocations-r16',
                {
                    'k': 'bits',
                    'size': [5, 5],
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SearchSpaceExt_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'monitoringSlotPeriodicityAndOffset-v1710',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'sl32',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 31,
                                'ext': False,
                            },
                        ],
                        [
                            'sl64',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 63,
                                'ext': False,
                            },
                        ],
                        [
                            'sl128',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 127,
                                'ext': False,
                            },
                        ],
                        [
                            'sl5120',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 5119,
                                'ext': False,
                            },
                        ],
                        [
                            'sl10240',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 10239,
                                'ext': False,
                            },
                        ],
                        [
                            'sl20480',
                            {
                                'k': 'int',
                                'lb': 0,
                                'ub': 20479,
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'monitoringSlotsWithinSlotGroup-r17',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'slotGroupLength4-r17',
                            {
                                'k': 'bits',
                                'size': [4, 4],
                                'ext': False,
                            },
                        ],
                        [
                            'slotGroupLength8-r17',
                            {
                                'k': 'bits',
                                'size': [8, 8],
                                'ext': False,
                            },
                        ],
                    ],
                    'extadd': [],
                },
                True,
                None,
            ],
            [
                'duration-r17',
                {
                    'k': 'int',
                    'lb': 4,
                    'ub': 20476,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'searchSpaceType-r17',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'common-r17',
                            {
                                'k': 'seq',
                                'ext': False,
                                'comp': [
                                    [
                                        'dci-Format4-0-r17',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format4-1-r17',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format4-2-r17',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format4-1-AndFormat4-2-r17',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
                                        },
                                        True,
                                        None,
                                    ],
                                    [
                                        'dci-Format2-7-r17',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [
                                                [
                                                    'nrofCandidates-PEI-r17',
                                                    {
                                                        'k': 'seq',
                                                        'ext': False,
                                                        'comp': [
                                                            [
                                                                'aggregationLevel4-r17',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n0', 'n1', 'n2', 'n3', 'n4'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel8-r17',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n0', 'n1', 'n2'],
                                                                    'ext': None,
                                                                },
                                                                True,
                                                                None,
                                                            ],
                                                            [
                                                                'aggregationLevel16-r17',
                                                                {
                                                                    'k': 'enum',
                                                                    'names': ['n0', 'n1'],
                                                                    'ext': None,
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
                True,
                None,
            ],
            [
                'searchSpaceGroupIdList-r17',
                {
                    'k': 'seqof',
                    'size': [1, 3],
                    'ext': False,
                    'of': {
                        'k': 'int',
                        'lb': 0,
                        'ub': 2,
                        'ext': False,
                    },
                },
                True,
                None,
            ],
            [
                'searchSpaceLinkingId-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 39,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SearchSpaceExt_v1800': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'searchSpaceType-r18',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'common-r18',
                            {
                                'k': 'seq',
                                'ext': True,
                                'comp': [
                                    [
                                        'dci-Format2-9-r18',
                                        {
                                            'k': 'seq',
                                            'ext': True,
                                            'comp': [],
                                            'extadd': [],
                                        },
                                        True,
                                        None,
                                    ],
                                ],
                                'extadd': [],
                            },
                        ],
                        [
                            'ue-Specific-r18',
                            {
                                'k': 'seq',
                                'ext': True,
                                'comp': [
                                    [
                                        'dci-FormatsMC-r18',
                                        {
                                            'k': 'enum',
                                            'names': ['formats0-3', 'formats1-3', 'formats0-3-And-1-3'],
                                            'ext': None,
                                        },
                                        True,
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
        ],
        'extadd': [],
    },
    'SearchSpaceId': {
        'k': 'int',
        'lb': 0,
        'ub': 39,
        'ext': False,
    },
    'SearchSpaceZero': {
        'k': 'int',
        'lb': 0,
        'ub': 15,
        'ext': False,
    },
    'SemiStaticChannelAccessConfig_r16': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'period-r16',
                {
                    'k': 'enum',
                    'names': ['ms1', 'ms2', 'ms2dot5', 'ms4', 'ms5', 'ms10'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'ServingCellConfigCommonSIB': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'downlinkConfigCommon',
                {
                    'k': 'ref',
                    't': 'DownlinkConfigCommonSIB',
                },
                False,
                None,
            ],
            [
                'uplinkConfigCommon',
                {
                    'k': 'ref',
                    't': 'UplinkConfigCommonSIB',
                },
                True,
                None,
            ],
            [
                'supplementaryUplink',
                {
                    'k': 'ref',
                    't': 'UplinkConfigCommonSIB',
                },
                True,
                None,
            ],
            [
                'n-TimingAdvanceOffset',
                {
                    'k': 'enum',
                    'names': ['n0', 'n25600', 'n39936'],
                    'ext': None,
                },
                True,
                None,
            ],
            [
                'ssb-PositionsInBurst',
                {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'inOneGroup',
                            {
                                'k': 'bits',
                                'size': [8, 8],
                                'ext': False,
                            },
                            False,
                            None,
                        ],
                        [
                            'groupPresence',
                            {
                                'k': 'bits',
                                'size': [8, 8],
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
                'ssb-PeriodicityServingCell',
                {
                    'k': 'enum',
                    'names': ['ms5', 'ms10', 'ms20', 'ms40', 'ms80', 'ms160'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'tdd-UL-DL-ConfigurationCommon',
                {
                    'k': 'ref',
                    't': 'TDD_UL_DL_ConfigCommon',
                },
                True,
                None,
            ],
            [
                'ss-PBCH-BlockPower',
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
        'extadd': [
            {
                'k': 'extgrp',
                'names': [
                    'channelAccessMode-r16',
                    'discoveryBurstWindowLength-r16',
                    'highSpeedConfig-r16',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'channelAccessMode-r16',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'dynamic',
                                        {
                                            'k': 'null',
                                        },
                                    ],
                                    [
                                        'semiStatic',
                                        {
                                            'k': 'ref',
                                            't': 'SemiStaticChannelAccessConfig_r16',
                                        },
                                    ],
                                ],
                                'extadd': [],
                            },
                            True,
                            None,
                        ],
                        [
                            'discoveryBurstWindowLength-r16',
                            {
                                'k': 'enum',
                                'names': ['ms0dot5', 'ms1', 'ms2', 'ms3', 'ms4', 'ms5'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'highSpeedConfig-r16',
                            {
                                'k': 'ref',
                                't': 'HighSpeedConfig_r16',
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
                    'channelAccessMode2-r17',
                    'discoveryBurstWindowLength-v1700',
                    'highSpeedConfigFR2-r17',
                    'uplinkConfigCommon-v1700',
                ],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'channelAccessMode2-r17',
                            {
                                'k': 'enum',
                                'names': ['enabled'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'discoveryBurstWindowLength-v1700',
                            {
                                'k': 'enum',
                                'names': ['ms0dot125', 'ms0dot25', 'ms0dot5', 'ms0dot75', 'ms1', 'ms1dot25'],
                                'ext': None,
                            },
                            True,
                            None,
                        ],
                        [
                            'highSpeedConfigFR2-r17',
                            {
                                'k': 'ref',
                                't': 'HighSpeedConfigFR2_r17',
                            },
                            True,
                            None,
                        ],
                        [
                            'uplinkConfigCommon-v1700',
                            {
                                'k': 'ref',
                                't': 'UplinkConfigCommonSIB_v1700',
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
                'names': ['enhancedMeasurementNGSO-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'enhancedMeasurementNGSO-r17',
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
                'names': ['ra-ChannelAccess-r17'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'ra-ChannelAccess-r17',
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
                'names': ['downlinkConfigCommon-v1760', 'uplinkConfigCommon-v1760'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'downlinkConfigCommon-v1760',
                            {
                                'k': 'ref',
                                't': 'DownlinkConfigCommonSIB_v1760',
                            },
                            True,
                            None,
                        ],
                        [
                            'uplinkConfigCommon-v1760',
                            {
                                'k': 'ref',
                                't': 'UplinkConfigCommonSIB_v1760',
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
    'SliceCellListNR_r17': {
        'k': 'seqof',
        'size': [1, 16],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'PCI_Range',
        },
    },
    'SliceInfoList_r17': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'SliceInfo_r17',
        },
    },
    'SliceInfo_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'nsag-IdentityInfo-r17',
                {
                    'k': 'ref',
                    't': 'NSAG_IdentityInfo_r17',
                },
                False,
                None,
            ],
            [
                'nsag-CellReselectionPriority-r17',
                {
                    'k': 'ref',
                    't': 'CellReselectionPriority',
                },
                True,
                None,
            ],
            [
                'nsag-CellReselectionSubPriority-r17',
                {
                    'k': 'ref',
                    't': 'CellReselectionSubPriority',
                },
                True,
                None,
            ],
            [
                'sliceCellListNR-r17',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'sliceAllowedCellListNR-r17',
                            {
                                'k': 'ref',
                                't': 'SliceCellListNR_r17',
                            },
                        ],
                        [
                            'sliceExcludedCellListNR-r17',
                            {
                                'k': 'ref',
                                't': 'SliceCellListNR_r17',
                            },
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
    'SpeedStateScaleFactors': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'sf-Medium',
                {
                    'k': 'enum',
                    'names': ['oDot25', 'oDot5', 'oDot75', 'lDot0'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'sf-High',
                {
                    'k': 'enum',
                    'names': ['oDot25', 'oDot5', 'oDot75', 'lDot0'],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'SubcarrierSpacing': {
        'k': 'enum',
        'names': [
            'kHz15',
            'kHz30',
            'kHz60',
            'kHz120',
            'kHz240',
            'kHz480-v1700',
            'kHz960-v1700',
            'spare1',
        ],
        'ext': None,
    },
    'SubgroupConfig_r17': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'subgroupsNumPerPO-r17',
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
                'subgroupsNumForUEID-r17',
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
    'SystemInformation': {
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
                            'systemInformation',
                            {
                                'k': 'ref',
                                't': 'SystemInformation_IEs',
                            },
                        ],
                        [
                            'criticalExtensionsFuture-r16',
                            {
                                'k': 'choice',
                                'ext': False,
                                'alts': [
                                    [
                                        'posSystemInformation-r16',
                                        {
                                            'k': 'ref',
                                            't': 'PosSystemInformation_r16_IEs',
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
    'SystemInformation_IEs': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'sib-TypeAndInfo',
                {
                    'k': 'seqof',
                    'size': [1, 32],
                    'ext': False,
                    'of': {
                        'k': 'choice',
                        'ext': True,
                        'alts': [
                            [
                                'sib2',
                                {
                                    'k': 'ref',
                                    't': 'SIB2',
                                },
                            ],
                            [
                                'sib3',
                                {
                                    'k': 'ref',
                                    't': 'SIB3',
                                },
                            ],
                            [
                                'sib4',
                                {
                                    'k': 'ref',
                                    't': 'SIB4',
                                },
                            ],
                            [
                                'sib5',
                                {
                                    'k': 'ref',
                                    't': 'SIB5',
                                },
                            ],
                            [
                                'sib6',
                                {
                                    'k': 'ref',
                                    't': 'SIB6',
                                },
                            ],
                            [
                                'sib7',
                                {
                                    'k': 'ref',
                                    't': 'SIB7',
                                },
                            ],
                            [
                                'sib8',
                                {
                                    'k': 'ref',
                                    't': 'SIB8',
                                },
                            ],
                            [
                                'sib9',
                                {
                                    'k': 'ref',
                                    't': 'SIB9',
                                },
                            ],
                        ],
                        'extadd': [
                            [
                                'sib10-v1610',
                                {
                                    'k': 'ref',
                                    't': 'SIB10_r16',
                                },
                            ],
                            [
                                'sib11-v1610',
                                {
                                    'k': 'ref',
                                    't': 'SIB11_r16',
                                },
                            ],
                            [
                                'sib12-v1610',
                                {
                                    'k': 'ref',
                                    't': 'SIB12_r16',
                                },
                            ],
                            [
                                'sib13-v1610',
                                {
                                    'k': 'ref',
                                    't': 'SIB13_r16',
                                },
                            ],
                            [
                                'sib14-v1610',
                                {
                                    'k': 'ref',
                                    't': 'SIB14_r16',
                                },
                            ],
                            [
                                'sib15-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIB15_r17',
                                },
                            ],
                            [
                                'sib16-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIB16_r17',
                                },
                            ],
                            [
                                'sib17-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIB17_r17',
                                },
                            ],
                            [
                                'sib18-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIB18_r17',
                                },
                            ],
                            [
                                'sib19-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIB19_r17',
                                },
                            ],
                            [
                                'sib20-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIB20_r17',
                                },
                            ],
                            [
                                'sib21-v1700',
                                {
                                    'k': 'ref',
                                    't': 'SIB21_r17',
                                },
                            ],
                            [
                                'sib22-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIB22_r18',
                                },
                            ],
                            [
                                'sib23-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIB23_r18',
                                },
                            ],
                            [
                                'sib24-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIB24_r18',
                                },
                            ],
                            [
                                'sib25-v1800',
                                {
                                    'k': 'ref',
                                    't': 'SIB25_r18',
                                },
                            ],
                            [
                                'sib17bis-v1820',
                                {
                                    'k': 'ref',
                                    't': 'SIB17bis_r18',
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
    'TA_Info_r17': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'ta-Common-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 66485757,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'ta-CommonDrift-r17',
                {
                    'k': 'int',
                    'lb': -257303,
                    'ub': 257303,
                    'ext': False,
                },
                True,
                None,
            ],
            [
                'ta-CommonDriftVariant-r17',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 28949,
                    'ext': False,
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'TCI_StateId': {
        'k': 'int',
        'lb': 0,
        'ub': 127,
        'ext': False,
    },
    'TDD_UL_DL_ConfigCommon': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'referenceSubcarrierSpacing',
                {
                    'k': 'ref',
                    't': 'SubcarrierSpacing',
                },
                False,
                None,
            ],
            [
                'pattern1',
                {
                    'k': 'ref',
                    't': 'TDD_UL_DL_Pattern',
                },
                False,
                None,
            ],
            [
                'pattern2',
                {
                    'k': 'ref',
                    't': 'TDD_UL_DL_Pattern',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'TDD_UL_DL_Pattern': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'dl-UL-TransmissionPeriodicity',
                {
                    'k': 'enum',
                    'names': ['ms0p5', 'ms0p625', 'ms1', 'ms1p25', 'ms2', 'ms2p5', 'ms5', 'ms10'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'nrofDownlinkSlots',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 320,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'nrofDownlinkSymbols',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 13,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'nrofUplinkSlots',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 320,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'nrofUplinkSymbols',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 13,
                    'ext': False,
                },
                False,
                None,
            ],
        ],
        'extadd': [
            {
                'k': 'extgrp',
                'names': ['dl-UL-TransmissionPeriodicity-v1530'],
                'node': {
                    'k': 'seq',
                    'ext': False,
                    'comp': [
                        [
                            'dl-UL-TransmissionPeriodicity-v1530',
                            {
                                'k': 'enum',
                                'names': ['ms3', 'ms4'],
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
    'TN_AreaId_r18': {
        'k': 'int',
        'lb': 1,
        'ub': 32,
        'ext': False,
    },
    'T_Reselection': {
        'k': 'int',
        'lb': 0,
        'ub': 7,
        'ext': False,
    },
    'ThresholdNR': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'thresholdRSRP',
                {
                    'k': 'ref',
                    't': 'RSRP_Range',
                },
                True,
                None,
            ],
            [
                'thresholdRSRQ',
                {
                    'k': 'ref',
                    't': 'RSRQ_Range',
                },
                True,
                None,
            ],
            [
                'thresholdSINR',
                {
                    'k': 'ref',
                    't': 'SINR_Range',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'TimeAlignmentTimer': {
        'k': 'enum',
        'names': [
            'ms500',
            'ms750',
            'ms1280',
            'ms1920',
            'ms2560',
            'ms5120',
            'ms10240',
            'infinity',
        ],
        'ext': None,
    },
    'TrackingAreaCode': {
        'k': 'bits',
        'size': [24, 24],
        'ext': False,
    },
    'UAC_AC1_SelectAssistInfo_r16': {
        'k': 'enum',
        'names': ['a', 'b', 'c', 'notConfigured'],
        'ext': None,
    },
    'UAC_AccessCategory1_SelectionAssistanceInfo': {
        'k': 'enum',
        'names': ['a', 'b', 'c'],
        'ext': None,
    },
    'UAC_BarringInfoSet': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'uac-BarringFactor',
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
                'uac-BarringTime',
                {
                    'k': 'enum',
                    'names': ['s4', 's8', 's16', 's32', 's64', 's128', 's256', 's512'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'uac-BarringForAccessIdentity',
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
    'UAC_BarringInfoSetIndex': {
        'k': 'int',
        'lb': 1,
        'ub': 8,
        'ext': False,
    },
    'UAC_BarringInfoSetList': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'UAC_BarringInfoSet',
        },
    },
    'UAC_BarringInfoSetList_v1700': {
        'k': 'seqof',
        'size': [1, 8],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'UAC_BarringInfoSet_v1700',
        },
    },
    'UAC_BarringInfoSet_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'uac-BarringFactorForAI3-r17',
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
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'UAC_BarringPerCat': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'accessCategory',
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
                'uac-barringInfoSetIndex',
                {
                    'k': 'ref',
                    't': 'UAC_BarringInfoSetIndex',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'UAC_BarringPerCatList': {
        'k': 'seqof',
        'size': [1, 63],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'UAC_BarringPerCat',
        },
    },
    'UAC_BarringPerPLMN': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'plmn-IdentityIndex',
                {
                    'k': 'int',
                    'lb': 1,
                    'ub': 12,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'uac-ACBarringListType',
                {
                    'k': 'choice',
                    'ext': False,
                    'alts': [
                        [
                            'uac-ImplicitACBarringList',
                            {
                                'k': 'seqof',
                                'size': [63, 63],
                                'ext': False,
                                'of': {
                                    'k': 'ref',
                                    't': 'UAC_BarringInfoSetIndex',
                                },
                            },
                        ],
                        [
                            'uac-ExplicitACBarringList',
                            {
                                'k': 'ref',
                                't': 'UAC_BarringPerCatList',
                            },
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
    'UAC_BarringPerPLMN_List': {
        'k': 'seqof',
        'size': [1, 12],
        'ext': False,
        'of': {
            'k': 'ref',
            't': 'UAC_BarringPerPLMN',
        },
    },
    'UE_TimersAndConstants': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                't300',
                {
                    'k': 'enum',
                    'names': [
                        'ms100',
                        'ms200',
                        'ms300',
                        'ms400',
                        'ms600',
                        'ms1000',
                        'ms1500',
                        'ms2000',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't301',
                {
                    'k': 'enum',
                    'names': [
                        'ms100',
                        'ms200',
                        'ms300',
                        'ms400',
                        'ms600',
                        'ms1000',
                        'ms1500',
                        'ms2000',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't310',
                {
                    'k': 'enum',
                    'names': ['ms0', 'ms50', 'ms100', 'ms200', 'ms500', 'ms1000', 'ms2000'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'n310',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n3', 'n4', 'n6', 'n8', 'n10', 'n20'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't311',
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
                'n311',
                {
                    'k': 'enum',
                    'names': ['n1', 'n2', 'n3', 'n4', 'n5', 'n6', 'n8', 'n10'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                't319',
                {
                    'k': 'enum',
                    'names': [
                        'ms100',
                        'ms200',
                        'ms300',
                        'ms400',
                        'ms600',
                        'ms1000',
                        'ms1500',
                        'ms2000',
                    ],
                    'ext': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'UplinkConfigCommonSIB': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'frequencyInfoUL',
                {
                    'k': 'ref',
                    't': 'FrequencyInfoUL_SIB',
                },
                False,
                None,
            ],
            [
                'initialUplinkBWP',
                {
                    'k': 'ref',
                    't': 'BWP_UplinkCommon',
                },
                False,
                None,
            ],
            [
                'timeAlignmentTimerCommon',
                {
                    'k': 'ref',
                    't': 'TimeAlignmentTimer',
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'UplinkConfigCommonSIB_v1700': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'initialUplinkBWP-RedCap-r17',
                {
                    'k': 'ref',
                    't': 'BWP_UplinkCommon',
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'UplinkConfigCommonSIB_v1760': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'frequencyInfoUL-v1760',
                {
                    'k': 'ref',
                    't': 'FrequencyInfoUL_SIB_v1760',
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
}
