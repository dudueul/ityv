# 행동 명세 수확 / Behavior Specification Harvest

> English summary: Every test function in the K-Ballot Python suites (373 found: tests 111, tests_v7 71, tests_v8 74, tests_v9 62, tests_v9_1 55, local_lab 17) is listed with an ITYV-BEH id, the invariant it encodes restated in ityv terms, a disposition (유지 keep, 수정 adapt, 폐기 drop with reason), the target crate and the ladder level at which the invariant must be evidenced. No test code is copied; only the behavioral intent is harvested. These rows become property tests, Kani harnesses or simulator scenarios in the named crates.

상태: 초안 v0.1 (ADR-0008). 원 테스트의 이름만 인용하며 코드는 가져오지 않는다.

## 0. 집계

| 항목 | 값 |
|---|---|
| 발견된 테스트 함수 | 373 |
| 유지 | 302 |
| 수정 | 52 |
| 폐기 | 19 |

폐기 사유 코드: `D-ARTIFACT`(K-Ballot 산출물 자체의 메타 검사), `D-COMPONENT`(ityv에 없는 구성요소), `D-JSON`(JSON 정규화 전용, 이진 인코딩으로 대체), `D-DEMO`(데모 픽스처 전용).

## 1. 명부·위협 등록부 메타 (tests/test_korea_threat_registry, test_v6_threat_completeness, tests_v7/test_repository_contracts)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-001 | tests/test_all_132_cases_present | 등록부의 모든 ID가 존재한다 | 폐기 D-ARTIFACT | — | — |
| ITYV-BEH-002 | tests/test_20_korea_cases_are_present_in_merged | 한국 특화 항목이 병합본에 있다 | 폐기 D-ARTIFACT | — | — |
| ITYV-BEH-003 | tests/test_no_duplicate_case_ids | 등록부 ID는 유일하다 | 수정: ITYV-THR·REQ ID 유일성을 문서 CI로 검사 | docs CI | V1 |
| ITYV-BEH-004 | tests/test_112_rows | 등록부 행 수가 고정값이다 | 폐기 D-ARTIFACT | — | — |
| ITYV-BEH-005 | tests/test_unique_ids | ID 유일성 | 수정: ITYV-BEH-003과 병합 | docs CI | V1 |
| ITYV-BEH-006 | tests/test_required_equal_swap_threats | 동일 수량 교체 위협이 등록부에 반드시 있다 | 수정: ITYV-THR-053·147의 존재를 문서 CI로 검사 | docs CI | V1 |
| ITYV-BEH-007 | tests/test_all_have_prevention_and_residual | 모든 위협에 대응과 잔여 위험이 있다 | 유지: THREAT_HARVEST 열 비어 있음 금지 | docs CI | V1 |
| ITYV-BEH-008 | tests/test_real_election_release_blockers_exist | 미해결 게이트가 하나라도 있으면 NO_GO다 | 유지 | docs CI, `ityv-state` 상태 어휘 | V1 |
| ITYV-BEH-009 | tests_v7/test_no_production_certification_claim | 어떤 산출물도 인증을 주장하지 않는다 | 유지: 문구 검사 | docs CI | V1 |
| ITYV-BEH-010 | tests_v7/test_threat_register_is_complete_and_unique | 등록부 완전성·유일성 | 수정: ITYV-BEH-003과 병합 | docs CI | V1 |
| ITYV-BEH-011 | tests_v7/test_all_new_entries_are_spec_only_not_patched | 신규 항목은 구현 완료로 표기되지 않는다 | 수정: THREAT_HARVEST의 CLOSED_BY_DESIGN은 증거 ID 없이는 PROVEN이 아님을 검사 | docs CI | V1 |
| ITYV-BEH-012 | tests_v7/test_scanner_never_silently_upcases_credential | 입력을 자동 정규화하지 않는다 | 수정: 정규 인코딩은 어떤 정규화도 하지 않고 거부한다 | `ityv-encoding` | V2 |
| ITYV-BEH-013 | tests_v7/test_scanner_calls_exact_parser | 스캐너는 정확한 파서만 호출한다 | 수정: 커밋먼트 유닛 입력은 고정 스키마 디코더만 통과 | `ityv-cunit` | V2 |
| ITYV-BEH-014 | tests_v7/test_public_mirror_remains_unverified | 미러는 검증 전 UNVERIFIED다 | 유지: 검증기 기본 상태 `UNVERIFIED` | `ityv-verify` | V1 |
| ITYV-BEH-015 | tests_v7/test_critical_core_in_memory_is_still_release_blocker | 메모리 상태 Core는 차단 조건이다 | 폐기 D-COMPONENT(메모리 권위 상태 없음) | — | — |
| ITYV-BEH-016 | tests_v7/test_no_private_vote_choice_in_public_guard_allowlist | 공개 필드 허용 목록에 선택·신원이 없다 | 유지: 게시 스키마에 선택·투함 ID·라벨·시각 없음 | `ityv-encoding` 스키마, `ityv-verify` | V2 |
| ITYV-BEH-017 | tests_v7/test_legal_adjudication_schema_no_auto_invalidity | 법적 판정 스키마에 자동 무효 경로가 없다 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-018 | tests_v7/test_202_risks_with_unresolved_P0 | 미해결 P0가 남아 있다 | 유지: P0_GATES 전부 NOT_PROVEN이면 NO_GO | docs CI | V1 |

## 2. 관외 우편·카세트 (tests/test_korean_postal_intake)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-019 | test_good_handoff_and_delivery | 정상 발송·인계·수령은 수량 일치로 마감된다 | 유지 | `ityv-state`, 시뮬레이터 | V1 |
| ITYV-BEH-020 | test_missing_tracked_envelope | 발송 집합에만 있는 봉투는 HOLD다 | 수정: 봉투 라벨 대조에서 미수령은 `CAST_NOT_RECEIVED` 공개 집계 | 신뢰기관 집계 | V2 |
| ITYV-BEH-021 | test_extra_envelope_does_not_pass | 발송 집합에 없는 봉투는 수령 확정되지 않는다 | 유지 | 신뢰기관 집계 | V2 |
| ITYV-BEH-022 | test_duplicate_envelope_does_not_pass | 같은 봉투가 두 번 수령되지 않는다 | 유지: 라벨 유일성 | 신뢰기관 집계 | V2 |
| ITYV-BEH-023 | test_handoff_wrong_set_is_hold | 인계 집합 불일치는 HOLD다 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-024 | test_handoff_duplicate_is_hold | 중복 인계는 HOLD다 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-025 | test_cannot_substitute_two_people_same_org | 같은 조직 두 사람은 독립 서명이 아니다 | 유지: 임명 이벤트의 조직 비교 | `ityv-state` | V2 |
| ITYV-BEH-026 | test_cannot_accept_from_wrong_state | 잘못된 상태에서 수령 전이는 불가하다 | 유지: typestate | `ityv-state` | trybuild |
| ITYV-BEH-027 | test_public_data_no_pii | 공개 데이터에 개인정보가 없다 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-028 | test_close_blocks_more_inserts | 마감 뒤 투입 불가 | 유지 | `ityv-state` | trybuild |
| ITYV-BEH-029 | test_invalid_envelope_not_inserted | 형식 위반 봉투는 투입되지 않는다 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-030 | test_cassette_full_is_hold | 카세트 포화는 새 카세트 개시이며 재배열은 HOLD다 | 유지 | `ityv-state` | V1 |
| ITYV-BEH-031 | test_seal_mismatch_quarantines | 봉인 해시 불일치는 격리다 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-032 | test_correct_seal_counting_model | 봉인·수량 모델의 정상 경로 | 유지 | 시뮬레이터 | V1 |
| ITYV-BEH-033 | test_unexpected_open_is_hold | 예고되지 않은 개함은 HOLD다 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-034 | test_double_open_forbidden | 이중 개함 불가 | 유지 | `ityv-state` | trybuild |
| ITYV-BEH-035 | test_nighttime_not_a_security_signal | 야간 시각 자체는 보안 신호가 아니다 | 유지: 시각은 판정 입력이 아님 | `ityv-state` | V1 |
| ITYV-BEH-036 | test_duplicate_cassette_item_fails | 카세트 내 중복 항목 실패 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-037 | test_single_witness_forbidden | 단일 입회 서명은 불충분하다 | 유지: 이중 서명 인계 | `ityv-state` | V2 |
| ITYV-BEH-038 | test_wrong_status_not_accepted | 상태 어휘 밖 값은 거부된다 | 유지 | `ityv-encoding` | V2 |

## 3. 투표함·장부 안전성 (tests/test_security_properties, test_source_security_contracts)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-039 | test_duplicate_same_box | 같은 투표함의 중복 투함 ID는 격리된다 | 수정: credential → 투함 ID | `ityv-cunit`, `ityv-ledger` | V2 |
| ITYV-BEH-040 | test_unknown_invalid | 등록되지 않은 발행자의 기록은 거부된다 | 수정: 발급 집합 대신 genesis 장치 등록 | `ityv-ledger` | V2 |
| ITYV-BEH-041 | test_close_counts_mismatch_fail | 마감 수량 불일치는 실패다 | 수정: 종이·각인·기록·폐기 4자 일치 | `ityv-state` | V2 |
| ITYV-BEH-042 | test_close_marks_strips_mismatch | 종이 수와 스트립 수 불일치 | 수정: 스트립 → 각인 수 | `ityv-state` | V2 |
| ITYV-BEH-043 | test_close_unique_valid_less_than_paper | 유효 기록 수가 종이 수보다 적으면 실패 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-044 | test_duplicate_attempt_is_incident | 중복 시도는 사건이다 | 유지 | `ityv-ledger` | V1 |
| ITYV-BEH-045 | test_invalid_attempt_is_incident | 무효 입력 시도는 사건이다 | 유지 | `ityv-cunit` | V1 |
| ITYV-BEH-046 | test_closure_blocks_rescan | 마감 후 재스캔 불가 | 유지 | `ityv-state` | trybuild |
| ITYV-BEH-047 | test_two_distinct_officers | 마감에 서로 다른 두 서명 | 수정: 다른 조직 참관인 2 + 장치 서명 | `ityv-state` | V2 |
| ITYV-BEH-048 | test_reopening_disallowed | 재개봉 불가 | 유지 | `ityv-state` | trybuild |
| ITYV-BEH-049 | test_restart_closed_state | 재시작 후 마감 상태 보존 | 유지 | `ityv-cunit` | V2 |
| ITYV-BEH-050 | test_restart_corrupt_tail | 손상된 꼬리는 복구하지 않고 격리 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-051 | test_global_duplicate_conflict | 전역 중복은 양쪽 보존 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-052 | test_same_event_replay_idempotent | 동일 바이트 재전송은 멱등 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-053 | test_event_id_payload_collision | 같은 ID 다른 본문은 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-054 | test_missing_seq_rejected | 순번 누락 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-055 | test_after_close_rejected | 마감 후 이벤트 거부 | 유지: 마감은 상태기계의 전이 | `ityv-state` | V2 |
| ITYV-BEH-056 | test_missing_box_prevents_certification | 예상 투표함 누락은 완전성 실패 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-057 | test_pq_verification_missing_prevents_certification | 서명 미검증은 상태 전이를 막는다 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-058 | test_phy_custody_missing_prevents_certification | 보관 증거 누락은 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-059 | test_complete_controls_allow_model_certification | 모든 조건 충족 시에도 결과는 `CRYPTO_TALLY_VERIFIED`까지이며 `LEGAL_CERTIFIED`가 아니다 | 수정 | `ityv-verify` | V2 |
| ITYV-BEH-060 | test_mirror_truncate_detects | 미러 절단 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-061 | test_mirror_rewrite_detects | 미러 재작성 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-062 | test_log_append_only_ok | 정상 추가는 통과 | 유지 | `ityv-ledger` | V1 |
| ITYV-BEH-063 | test_random_mutation_invariant | 무작위 변이에도 불변식 유지 | 유지: proptest | `ityv-ledger`, `ityv-state` | V1 |
| ITYV-BEH-064 | test_rust_services_require_explicit_acknowledgement | 데모 실행에 명시 확인 필요 | 폐기 D-DEMO(릴리스에 데모 플래그 없음, 시뮬레이터 별도 바이너리) | — | — |
| ITYV-BEH-065 | test_scanner_requires_durable_coordinator | 내구 기록 없이 성공 표시 불가 | 수정: `DURABLE` 전 슬립 전이 불가 | `ityv-cunit` | trybuild, V2 |
| ITYV-BEH-066 | test_field_ui_has_no_untrusted_innerhtml | UI 스크립트 주입 없음 | 폐기 D-COMPONENT | — | — |
| ITYV-BEH-067 | test_worker_is_not_unverified_authority | 미러는 권위가 아니다 | 유지: ITYV-BEH-014 | `ityv-verify` | V1 |
| ITYV-BEH-068 | test_witness_does_not_auto_approve | 증인은 자동 승인하지 않는다 | 유지: 증인 정책 검사 후에만 서명 | 증인 도구 | V2 |
| ITYV-BEH-069 | test_manifest_builder_not_uuid_v4 | 식별자는 UUID가 아니라 192비트 CSPRNG | 수정: 투함 ID 생성은 봉인 모듈 192비트 | `ityv-cunit` | V1 |
| ITYV-BEH-070 | test_proof_checks_leaf_position | 증명은 리프 위치를 검사한다 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-071 | test_core_serializes_mutations | 변경은 직렬화된다 | 수정: 단일 작성자 장부 | `ityv-ledger` | V3 |
| ITYV-BEH-072 | test_core_accepts_authentic_replay_after_close | 마감 후 동일 바이트 재전송은 멱등 성공 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-073 | test_worker_quarantine_rejects_path_components | 입력 키에 경로 요소 거부 | 폐기 D-COMPONENT(식별자는 `Ident` 알파벳으로 대체) | — | — |

## 4. 종이 증거·수량 회계 (tests/test_v6_ballot_integrity)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-074 | test_clean_model_ready_not_real_certification | 정상 모델도 법적 인증이 아니다 | 유지 | `ityv-verify` | V1 |
| ITYV-BEH-075 | test_stuffing_detect | 추가 표는 수량 불일치로 탐지 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-076 | test_equal_count_swap_content_detect_if_baseline_preexists | 기준선이 있으면 동일 수량 교체가 탐지된다 | 수정: 기준선은 투함 시 커밋먼트, 감사 대조로 탐지 | 시뮬레이터, `ityv-verify` | V1 |
| ITYV-BEH-077 | test_equal_count_swap_unobservable_without_baseline | 기준선 없는 교체는 탐지 불가 | 수정: `RECEIPT_SCAN` 경로와 0·1단계에 한정해 상태로 표기 | `ityv-state` | V1 |
| ITYV-BEH-078 | test_first_baseline_not_anchored_does_not_claim_authenticity | 앵커 없는 기준선은 진정성을 주장하지 않는다 | 수정: 증인 체크포인트에 포함되지 않은 투함 기록은 `UNVERIFIED` | `ityv-verify` | V2 |
| ITYV-BEH-079 | test_cannot_create_late_baseline | 사후 기준선 생성 불가 | 유지: 마감 후 투함 기록 거부 | `ityv-ledger` | V2 |
| ITYV-BEH-080 | test_incident_on_inbound_seal_swap | 수령 시 봉인 교체는 사건 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-081 | test_one_signer_forbidden | 단일 서명 불충분 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-082 | test_same_org_two_people_not_independent | 같은 조직은 독립이 아님 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-083 | test_reused_eventid_forbidden | 이벤트 ID 재사용 불가 | 유지: 이벤트 색인은 상태기계 | `ityv-state` | V2 |
| ITYV-BEH-084 | test_reopen_after_open_forbidden | 재개봉 불가 | 유지 | `ityv-state` | trybuild |
| ITYV-BEH-085 | test_baseline_replacement_forbidden | 기준선 교체 불가 | 유지: 투함 기록 불변 | `ityv-ledger` | V2 |
| ITYV-BEH-086 | test_log_mutation_detect | 로그 변조 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-087 | test_unresolved_provisional_hold | 미해결 잠정 기록은 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-088 | test_duplicate_hold | 중복은 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-089 | test_preprinted_inventory_error | 인쇄 재고 등식 위반 탐지 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-090 | test_issued_inventory_error | 교부 등식 위반 탐지 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-091 | test_scanner_missed_ballot_error | 기록 수 < 종이 수 탐지 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-092 | test_credential_count_mismatch | 식별자 수 불일치 탐지 | 수정: 각인 수 | `ityv-state` | V2 |
| ITYV-BEH-093 | test_negative_count_rejected | 음수 수량 거부 | 유지: 부호 없는 정수만 존재 | `ityv-encoding` | V2 |
| ITYV-BEH-094 | test_bool_count_rejected | 불리언을 수량으로 거부 | 유지: 타입 분리 | `ityv-encoding` | V2 |
| ITYV-BEH-095 | test_all_security_gate_inputs_required | 모든 게이트 입력이 필수 | 유지: 검증기 입력 구조체에 Option 없음 | `ityv-verify` | V2 |
| ITYV-BEH-096 | test_public_proof_excludes_vote_and_user | 공개 증명에 선택·신원 없음 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-097 | test_journal_chaining | 저널 사슬 검증 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-098 | test_missing_custody_baseline_prevents_success | 보관 기준선 없으면 성공 불가 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-099 | test_custody_seal_open_broken | 봉인 파손 시 보관 실패 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-100 | test_close_is_simulated_with_no_signatures | 서명 없는 마감은 시뮬레이션일 뿐 | 수정: 서명 없는 마감 객체는 타입상 불가 | `ityv-state` | trybuild |
| ITYV-BEH-101 | test_randomized_invariant_mutations_hold | 무작위 변이 불변식 | 유지: proptest | `ityv-state` | V1 |
| ITYV-BEH-102 | test_cannot_certify_untrusted_paper_because_merkle_matches | Merkle 일치는 종이 진정성이 아니다 | 유지: 상태 어휘 | `ityv-verify` | V1 |
| ITYV-BEH-103 | test_absent_pq_status_hold | 서명 상태 부재는 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-104 | test_arbitrary_observer_identifier_rejected | 등록되지 않은 참관인 ID 거부 | 유지: 임명 이벤트 | `ityv-state` | V2 |

## 5. V7 보증 정책 (tests_v7/test_assurance_v7)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-105 | CredentialParsing.test_canonical | 정규 입력만 수락 | 수정: 정규 이진 인코딩 | `ityv-encoding` | V2 |
| ITYV-BEH-106 | CredentialParsing.test_control_characters | 제어문자 거부 | 수정: `Ident` 알파벳 밖 바이트 거부 | `ityv-encoding` | V2 |
| ITYV-BEH-107 | CredentialParsing.test_format_confusion | 형식 혼동 거부 | 수정: 스키마 ID·버전 검사 | `ityv-encoding` | V2 |
| ITYV-BEH-108 | CredentialParsing.test_unicode_confusables | 동형문자 거부 | 수정: ASCII 알파벳만 | `ityv-encoding` | V2 |
| ITYV-BEH-109 | CredentialParsing.test_non_text | 비텍스트 입력 거부 | 수정: 길이·헤더 검사 | `ityv-encoding` | V2 |
| ITYV-BEH-110 | WitnessPolicy.test_proposed_13_9_profile | 13 중 9 정족수 수학 | 유지 | `ityv-ledger`(`QuorumProfile`) | V2 |
| ITYV-BEH-111 | WitnessPolicy.test_proposed_19_13_profile | 19 중 13 프로필 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-112 | WitnessPolicy.test_bad_quorum_intersection_rejected | 교집합 부족 정족수 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-113 | WitnessPolicy.test_8_signers_not_enough | 8 서명 불충분 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-114 | WitnessPolicy.test_duplicated_signature_not_double_counted | 중복 서명자 미계산 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-115 | WitnessPolicy.test_same_provider_risk | 공급자 다양성 부족 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-116 | WitnessPolicy.test_same_org_collusion_risk | 조직 다양성 부족 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-117 | WitnessPolicy.test_same_territory_risk | 지역 다양성 부족 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-118 | WitnessPolicy.test_mixed_forks_cannot_form_one_quorum | 서로 다른 root의 서명은 한 정족수가 아니다 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-119 | WitnessPolicy.test_unverified_claim_never_counts_as_valid | 검증 주장 플래그는 무시 | 유지: 타입화된 결과 | `ityv-verify` | V2 |
| ITYV-BEH-120 | WitnessPolicy.test_spoofed_extra_witness_detected | 명단 밖 증인 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-121 | TransparencyPolicy.test_valid_next_head_with_external_consistency | 일관성 증명 있는 확장 수락 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-122 | TransparencyPolicy.test_stale_root_replay_fails | 오래된 root 재생 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-123 | TransparencyPolicy.test_same_seq_different_root_detected | 같은 순번 다른 root 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-124 | TransparencyPolicy.test_proof_not_implemented_fails_closed | 증명 없으면 실패 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-125 | TransparencyPolicy.test_gap_in_checkpoint_history | 체크포인트 순번 공백 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-126 | TransparencyPolicy.test_count_rollback_even_if_root_valid | 크기 감소는 root가 맞아도 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-127 | TransparencyPolicy.test_parent_hash_mismatch | 이전 해시 불일치 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-128 | TransparencyPolicy.test_cross_election_head | 다른 선거 헤드 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-129 | TransparencyPolicy.test_corrupt_root_rejected | 손상 root 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-130 | TransparencyPolicy.test_new_mirror_cannot_trust_first_head_by_tofu | 첫 헤드를 무조건 신뢰하지 않는다 | 유지: 외부 핀 필수 | `ityv-verify` | V2 |
| ITYV-BEH-131 | TransparencyPolicy.test_exact_idempotent_replay | 정확한 재생은 멱등 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-132 | DueProcess.test_duplicate_creates_case_not_automatic_invalidation | 중복은 사건이지 무효가 아니다 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-133 | DueProcess.test_case_cannot_begin_marked_resolved | 사건은 해결 상태로 시작할 수 없다 | 유지 | `ityv-state` | trybuild |
| ITYV-BEH-134 | DueProcess.test_case_event_id_not_replayed | 사건 ID 재생 불가 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-135 | DueProcess.test_one_reviewer_not_enough | 검토자 1명 불충분 | 수정: 선관위·독립검증위원회 공동 | `ityv-state` | V2 |
| ITYV-BEH-136 | DueProcess.test_disputes_require_appeal | 분쟁에 이의 경로 필수 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-137 | DueProcess.test_disputes_require_lawful_authority | 법적 결정에 권한 기관 서명 필수 | 유지: `LegalDecisionRef` | `ityv-state` | V2 |
| ITYV-BEH-138 | DueProcess.test_two_org_review_with_appeal | 두 조직 검토와 이의 경로 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-139 | DueProcess.test_malformed_evidence_hash_rejected | 손상 증거 해시 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-140 | DueProcess.test_machine_cannot_auto_disqualify | 기계는 자동 실격시키지 못한다 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-141 | DueProcess.test_unknown_human_review_is_pending | 검토 미완은 보류 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-142 | PrivacyAndFairness.test_safe_aggregate | 안전한 집계 단위 통과 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-143 | PrivacyAndFairness.test_minimum_aggregate_suppression | 최소 집계 단위 미만 억제 | 유지 | 신뢰기관 집계 | V2 |
| ITYV-BEH-144 | PrivacyAndFairness.test_no_preclose_result_release | 종료 전 결과 공개 불가 | 유지: 열기는 종료 이벤트 이후 | 신뢰기관 집계 | V2 |
| ITYV-BEH-145 | PrivacyAndFairness.test_nested_sensitive_data_leak | 중첩 민감 데이터 누출 차단 | 수정: 스키마에 자유 필드 없음 | `ityv-encoding` | V2 |
| ITYV-BEH-146 | PrivacyAndFairness.test_timing_correlation_leak | 시각 상관 누출 차단 | 수정: 투함 기록 시각 없음, 추적코드 순 정렬 | `ityv-verify` | V1 |
| ITYV-BEH-147 | PrivacyAndFairness.test_small_batch_and_early_result_are_separate_failures | 소규모와 조기 공개는 별개 실패 | 유지 | 신뢰기관 집계 | V2 |
| ITYV-BEH-148 | PrivacyAndFairness.test_ui_does_not_claim_individual_count_proof | UI가 개인 집계 증명을 주장하지 않는다 | 유지 | docs CI, apps | V1 |
| ITYV-BEH-149 | PrivacyAndFairness.test_unsigned_receipt_not_sold_as_proof | 서명 없는 슬립은 증거가 아니다 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-150 | PrivacyAndFairness.test_audit_not_complete_is_record_only | 감사 미완은 기록일 뿐 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-151 | PaperAndAdjudication.test_clean_model_account | 정상 회계 통과 | 유지 | `ityv-state` | V1 |
| ITYV-BEH-152 | PaperAndAdjudication.test_same_count_substitution_not_proven_without_earlier_baseline | 기준선 없으면 교체 비탐지 명시 | 수정: ITYV-BEH-077 | `ityv-state` | V1 |
| ITYV-BEH-153 | PaperAndAdjudication.test_equal_count_substitution_with_different_content_detected | 내용 다른 교체는 기준선 대조로 탐지 | 수정: 감사 대조 | 시뮬레이터 | V1 |
| ITYV-BEH-154 | PaperAndAdjudication.test_same_content_only_proves_baseline_match | 내용 일치는 기준선 일치만 증명 | 유지 | `ityv-verify` | V1 |
| ITYV-BEH-155 | PaperAndAdjudication.test_unanchored_baseline_does_not_count | 앵커 없는 기준선 무효 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-156 | PaperAndAdjudication.test_missing_after_handling_evidence | 사후 증거 누락은 비교 불가 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-157 | PaperAndAdjudication.test_added_papers_detectable_in_aggregate_model | 추가 종이 탐지 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-158 | PaperAndAdjudication.test_missing_papers_detectable | 누락 종이 탐지 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-159 | PaperAndAdjudication.test_checking_ballot_styles_required | 투표양식 확인 필수 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-160 | PaperAndAdjudication.test_negative_and_noninteger_rejected | 음수·비정수 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-161 | ReleaseGates.test_default_never_ready | 기본 상태는 준비 아님 | 유지 | `ityv-state` | V1 |
| ITYV-BEH-162 | ReleaseGates.test_simulated_evidence_is_not_a_real_verification | 시뮬레이션 증거는 검증이 아님 | 유지: 시뮬레이터 토큰은 별도 타입 | `ityv-state` | trybuild |
| ITYV-BEH-163 | ReleaseGates.test_every_external_gate_required | 모든 게이트 필수 | 유지 | docs CI | V1 |
| ITYV-BEH-164 | ReleaseGates.test_dispute_cannot_be_hidden | 분쟁은 숨길 수 없다 | 유지: 분쟁 root가 체크포인트에 결속 | `ityv-ledger` | V2 |
| ITYV-BEH-165 | ReleaseGates.test_model_ready_cannot_carry_legal_certification_claim | 모델 준비는 법적 인증이 아님 | 유지 | `ityv-state` | V1 |

## 6. V8 픽스처·종이·영속성·정규화·서명 (tests_v8)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-166 | FixtureChecks.test_genuine_pq_demo_offline | 실제 서명 벡터가 오프라인에서 검증된다 | 수정: 알려진 답 벡터(KAT) | `ityv-crypto` | V1 |
| ITYV-BEH-167 | FixtureChecks.test_public_fixture_tampered_root | root 변조 시 서명 실패 | 유지 | `ityv-crypto` | V1 |
| ITYV-BEH-168 | FixtureChecks.test_public_fixture_tampered_sig | 서명 변조 실패 | 유지 | `ityv-crypto` | V1 |
| ITYV-BEH-169 | FixtureChecks.test_public_fixture_unknown_witness | 미등록 증인 실패 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-170 | PhysicalEvidence.test_equal_quantity_swap_not_proved_secure | 동일 수량 교체는 수량만으로 안전 입증 불가 | 수정: 커밋먼트 대조 없이는 입증 불가로 표기 | `ityv-state` | V1 |
| ITYV-BEH-171 | PhysicalEvidence.test_equal_counts_custody_lost | 보관 사슬 단절 시 수량 일치도 HOLD | 유지 | `ityv-state` | V2 |
| ITYV-BEH-172 | PhysicalEvidence.test_broken_seal | 봉인 파손 HOLD | 유지 | `ityv-state` | V2 |
| ITYV-BEH-173 | PhysicalEvidence.test_duplicate | 중복 HOLD | 유지 | `ityv-state` | V2 |
| ITYV-BEH-174 | PhysicalEvidence.test_extra_paper | 추가 종이 탐지 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-175 | PhysicalEvidence.test_removed_paper | 제거 종이 탐지 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-176 | PhysicalEvidence.test_fake_baseline_not_trusted | 위조 기준선 불신 | 유지: 증인 포함 전 UNVERIFIED | `ityv-verify` | V2 |
| ITYV-BEH-177 | PhysicalEvidence.test_independently_authenticated_baseline_diff | 인증된 기준선과 차이는 조사 | 유지 | 시뮬레이터 | V1 |
| ITYV-BEH-178 | PhysicalEvidence.test_trusted_baseline_same_not_legal_certification | 기준선 일치도 법적 인증 아님 | 유지 | `ityv-state` | V1 |
| ITYV-BEH-179 | PhysicalEvidence.test_fake_number | 비정수 수량 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-180 | PersistenceAdversarialTests.test_issuance_immutability_after_restart | 재시작 후 기준정보 불변 | 수정: genesis 핀 | `ityv-verify` | V2 |
| ITYV-BEH-181 | PersistenceAdversarialTests.test_election_cross_session | 다른 선거 세션 분리 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-182 | PersistenceAdversarialTests.test_deleted_event_row_with_journal_preserved | 투영 삭제는 장부로 복구 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-183 | PersistenceAdversarialTests.test_altered_event_status_with_journal_preserved | 투영 상태 변조 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-184 | PersistenceAdversarialTests.test_closed_flag_reopening_tamper | 마감 플래그 변조 탐지 | 유지: 마감은 서명 이벤트 | `ityv-ledger` | V2 |
| ITYV-BEH-185 | PersistenceAdversarialTests.test_removed_conflict_record | 분쟁 기록 삭제 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-186 | PersistenceAdversarialTests.test_deleted_close_manifest | 마감 기록 삭제 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-187 | PersistenceAdversarialTests.test_altered_box_next_seq | 순번 변조 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-188 | PersistenceAdversarialTests.test_incomplete_evidence_cannot_certify | 불완전 증거는 전이 불가 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-189 | PersistenceAdversarialTests.test_checkpoint_proposal_binds_all_three_roots | 체크포인트가 이벤트·마감·분쟁 root를 모두 결속 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-190 | PersistenceAdversarialTests.test_partial_journal_tail_truncation | 꼬리 절단 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-191 | PersistenceAdversarialTests.test_empty_anchor_detects_complete_rollback | 빈 앵커로 완전 되감기 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-192 | PersistenceAdversarialTests.test_two_independent_sqlite_connections_serialize | 동시 접속 직렬화 | 수정: 단일 작성자 보장 | `ityv-ledger` | V3 |
| ITYV-BEH-193 | CanonicalTests.test_canonical_stable | 정규화 안정성 | 수정: 이진 왕복 | `ityv-encoding` | V2 |
| ITYV-BEH-194 | CanonicalTests.test_duplicate_json_rejected | 중복 키 거부 | 폐기 D-JSON | — | — |
| ITYV-BEH-195 | CanonicalTests.test_bad_utf8 | 잘못된 UTF-8 거부 | 폐기 D-JSON(문자열 없음) | — | — |
| ITYV-BEH-196 | CanonicalTests.test_nonfinite | 비유한 수 거부 | 폐기 D-JSON(부동소수점 없음) | — | — |
| ITYV-BEH-197 | CanonicalTests.test_extra_field | 추가 필드 거부 | 수정: 잉여 바이트 거부 | `ityv-encoding` | V2 |
| ITYV-BEH-198 | CanonicalTests.test_nonascii_id | 비ASCII ID 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-199 | CanonicalTests.test_float_sequence | 실수 순번 거부 | 수정: 고정폭 정수만 | `ityv-encoding` | V2 |
| ITYV-BEH-200 | CanonicalTests.test_bool_sequence | 불리언 순번 거부 | 수정: 타입 분리 | `ityv-encoding` | V2 |
| ITYV-BEH-201 | CanonicalTests.test_uppercase_hash | 대문자 16진 거부 | 폐기 D-JSON(해시는 바이트) | — | — |
| ITYV-BEH-202 | CanonicalTests.test_fake_genesis | 위조 genesis 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-203 | CanonicalTests.test_corrupt_field_hash | 손상 해시 필드 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-204 | CanonicalTests.test_domain_binding | 도메인 결속 | 유지 | `ityv-crypto` | V2 |
| ITYV-BEH-205 | CanonicalTests.test_oversized_json | 초과 크기 거부 | 수정: 스키마 최대 길이 | `ityv-encoding` | V2 |
| ITYV-BEH-206 | CanonicalTests.test_public_privacy_ban | 공개 금지 필드 차단 | 유지 | `ityv-encoding` 스키마 | V2 |
| ITYV-BEH-207 | EvidenceCoreTests.test_durable_restart | 재시작 후 내구 상태 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-208 | EvidenceCoreTests.test_replay_exact_idempotent | 정확한 재생 멱등 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-209 | EvidenceCoreTests.test_event_id_mutation_rejected | ID 변조 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-210 | EvidenceCoreTests.test_unknown_issued_commitment | 미등록 발행 거부 | 수정: genesis 장치 등록 | `ityv-ledger` | V2 |
| ITYV-BEH-211 | EvidenceCoreTests.test_bad_mac | 잘못된 인증 태그 거부 | 수정: 하이브리드 서명 | `ityv-crypto` | V2 |
| ITYV-BEH-212 | EvidenceCoreTests.test_global_duplicate_not_legal_invalidation | 전역 중복은 법적 무효가 아님 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-213 | EvidenceCoreTests.test_sequence_gap | 순번 공백 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-214 | EvidenceCoreTests.test_sequence_reuse | 순번 재사용 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-215 | EvidenceCoreTests.test_empty_reconciliation | 빈 대조는 성공이 아님 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-216 | EvidenceCoreTests.test_physical_substitution_cannot_be_detected_by_count_only | 수량만으로 교체 비탐지 | 수정: 커밋먼트 대조 필요 표기 | `ityv-state` | V1 |
| ITYV-BEH-217 | EvidenceCoreTests.test_physical_mismatch | 물리 불일치 HOLD | 유지 | `ityv-state` | V2 |
| ITYV-BEH-218 | EvidenceCoreTests.test_event_after_close | 마감 후 이벤트 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-219 | EvidenceCoreTests.test_cross_election | 교차 선거 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-220 | EvidenceCoreTests.test_invalid_close_operator_dupe | 마감 서명자 중복 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-221 | EvidenceCoreTests.test_unsigned_identity_cannot_make_final | 서명 없는 신원은 확정 불가 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-222 | EvidenceCoreTests.test_reopened_closed_state | 마감 상태 재개 불가 | 유지 | `ityv-state` | trybuild |
| ITYV-BEH-223 | EvidenceCoreTests.test_external_anchor_detects_journal_tamper | 외부 앵커로 변조 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-224 | EvidenceCoreTests.test_rollback_anchor_detection | 되감기 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-225 | EvidenceCoreTests.test_journal_root_nonempty | 빈 로그 root 처리 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-226 | OpenSSLVerificationTests.test_valid_real_pq_quorum | 실제 정족수 서명 검증 | 수정: KAT + 하이브리드 | `ityv-crypto` | V1 |
| ITYV-BEH-227 | OpenSSLVerificationTests.test_corrupt_signature | 서명 손상 거부 | 유지 | `ityv-crypto` | V1 |
| ITYV-BEH-228 | OpenSSLVerificationTests.test_signature_not_reusable_other_election | 서명 교차 선거 재사용 불가 | 유지 | `ityv-crypto` | V2 |
| ITYV-BEH-229 | OpenSSLVerificationTests.test_duplicate_signer | 중복 서명자 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-230 | OpenSSLVerificationTests.test_too_few | 서명 부족 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-231 | OpenSSLVerificationTests.test_pinned_roster_different_key | 명단 키 불일치 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-232 | OpenSSLVerificationTests.test_wrong_algorithm | 알고리즘 불일치 거부 | 유지 | `ityv-crypto` | V2 |
| ITYV-BEH-233 | OpenSSLVerificationTests.test_modified_root | root 변경 거부 | 유지 | `ityv-crypto` | V1 |
| ITYV-BEH-234 | OpenSSLVerificationTests.test_quorum_other_keyset | 다른 키 집합 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-235 | OpenSSLVerificationTests.test_unknown_signer | 미등록 서명자 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-236 | OpenSSLVerificationTests.test_diversity_requirement | 다양성 요건 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-237 | OpenSSLVerificationTests.test_witness_anti_equivocation_persists | 증인 이중 서명 금지 영속 | 유지 | 증인 도구 | V2 |
| ITYV-BEH-238 | OpenSSLVerificationTests.test_witness_prefix_rewrite | 접두부 재작성 거부 | 유지 | 증인 도구 | V2 |
| ITYV-BEH-239 | OpenSSLVerificationTests.test_empty_log_root | 빈 로그 root | 유지 | `ityv-ledger` | V2 |

## 7. V9 장부·인증·PQC 모니터 (tests_v9)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-240 | LedgerTest.test_empty_anchor | 빈 장부의 앵커가 정의된다 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-241 | LedgerTest.test_append | 추가 후 헤드·크기 갱신 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-242 | LedgerTest.test_competing_appenders_use_locked_current_head | 경쟁 작성자는 잠긴 최신 헤드를 쓴다 | 수정: 단일 작성자 보장으로 대체 | `ityv-ledger` | V3 |
| ITYV-BEH-243 | LedgerTest.test_concurrent_duplicate_same_event_only_one_record | 동시 중복은 한 기록만 | 유지 | `ityv-ledger` | V3 |
| ITYV-BEH-244 | LedgerTest.test_recover | 재시작 복구 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-245 | LedgerTest.test_repeated_event_idempotent | 반복 이벤트 멱등 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-246 | LedgerTest.test_duplicate_id_changed_payload_rejected | 같은 ID 다른 본문 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-247 | LedgerTest.test_no_raw_credential | 장부에 원시 식별자 없음 | 수정: 투함 ID는 커밋먼트 안에만 | `ityv-encoding` 스키마 | V2 |
| ITYV-BEH-248 | LedgerTest.test_no_voter_personal_data | 장부에 개인정보 없음 | 유지 | `ityv-encoding` 스키마 | V2 |
| ITYV-BEH-249 | LedgerTest.test_no_candidate_selection | 장부에 선택 없음 | 유지 | `ityv-encoding` 스키마 | V2 |
| ITYV-BEH-250 | LedgerTest.test_reject_invalid_type | 등록되지 않은 이벤트 종류 거부 | 유지: 스키마 ID 등록부 | `ityv-encoding` | V2 |
| ITYV-BEH-251 | LedgerTest.test_reject_invalid_election | 다른 선거 ID 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-252 | LedgerTest.test_reject_unicode_confusable_id | 동형문자 ID 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-253 | LedgerTest.test_reject_invalid_sha | 잘못된 해시 길이 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-254 | LedgerTest.test_bad_anchor | 잘못된 앵커 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-255 | LedgerTest.test_missing_segment_detected_by_anchor | 세그먼트 누락 앵커 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-256 | LedgerTest.test_corrupt_record | 손상 프레임 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-257 | LedgerTest.test_truncated_header | 잘린 헤더 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-258 | LedgerTest.test_truncated_record | 잘린 프레임 거부·비복구 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-259 | LedgerTest.test_reorder_records_rejected | 순서 변경 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-260 | LedgerTest.test_external_anchor_detects_rewrite_even_if_chain_recomputed | 사슬을 재계산해도 외부 앵커가 재작성을 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-261 | LedgerTest.test_projection_rebuild | 투영 재구축 | 유지 | `ityv-ledger` | V1 |
| ITYV-BEH-262 | LedgerTest.test_db_owner_tamper_recovered_from_witnessed_log | 투영 변조는 증인 로그로 복구 | 유지 | `ityv-ledger` | V1 |
| ITYV-BEH-263 | LedgerTest.test_rebuild_refuses_without_valid_external_anchor | 앵커 없이 재구축 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-264 | CertificationTest.test_valid_box | 정상 투표함 마감 통과 | 수정: 하이브리드 서명 | `ityv-state` | V1 |
| ITYV-BEH-265 | CertificationTest.test_bad_box_key | 잘못된 장치 키 거부 | 유지 | `ityv-crypto` | V2 |
| ITYV-BEH-266 | CertificationTest.test_missing_observer | 참관인 부족 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-267 | CertificationTest.test_bad_observer | 잘못된 참관인 서명 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-268 | CertificationTest.test_unknown_box | 미등록 투표함 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-269 | CertificationTest.test_wrong_election | 다른 선거 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-270 | CertificationTest.test_count_mismatch | 수량 불일치 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-271 | CertificationTest.test_complete_gate_is_not_legal_certification | 완전한 게이트도 법적 인증 아님 | 유지 | `ityv-verify` | V1 |
| ITYV-BEH-272 | CertificationTest.test_source_close_omitted_from_global_log | 마감 기록 누락 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-273 | CertificationTest.test_source_close_replaced_in_global_log | 마감 기록 교체 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-274 | CertificationTest.test_missing_box | 투표함 누락 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-275 | CertificationTest.test_duplicate_box | 투표함 중복 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-276 | CertificationTest.test_witness_fail | 증인 정족수 실패 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-277 | CertificationTest.test_mirror_split | 미러 분기 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-278 | CertificationTest.test_only_two_archives | 보관소 2곳은 부족 | 유지: 최소 3 | `ityv-verify` | V2 |
| ITYV-BEH-279 | CertificationTest.test_conflict_holds_not_automatically_invalidated | 분쟁은 보류이지 무효 아님 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-280 | CertificationTest.test_paper_audit_required | 종이 감사 없이는 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-281 | CertificationTest.test_custody_incident_required | 보관 사건 미해결은 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-282 | CertificationTest.test_mirror_witness_root_mismatch | 미러·증인 root 불일치 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-283 | CertificationTest.test_quorum_math_13_9 | 정족수 교집합 수학 | 유지 | `ityv-crypto` | V2 |
| ITYV-BEH-284 | CertificationTest.test_quorum_9_13_availability | 5곳 불가용 시 정족수 불가 | 유지 | `ityv-crypto` | V2 |
| ITYV-BEH-285 | PQFixtureTest.test_roster_swap_rejected_before_signature_checks | 명단 교체는 서명 검사 전에 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-286 | PQFixtureTest.test_genuine_v9_pqc_quorum | 실제 정족수 서명 검증 | 수정: KAT | `ityv-crypto` | V1 |
| ITYV-BEH-287 | PQFixtureTest.test_direct_signature_verify | 직접 서명 검증 | 유지 | `ityv-crypto` | V1 |
| ITYV-BEH-288 | PQFixtureTest.test_bad_body_invalid_signature | 본문 변조 서명 실패 | 유지 | `ityv-crypto` | V1 |
| ITYV-BEH-289 | PQFixtureTest.test_bad_pubkey_in_roster | 명단 공개키 손상 거부 | 유지 | `ityv-encoding` | V2 |
| ITYV-BEH-290 | PQFixtureTest.test_duplicate_witness_not_counted | 중복 증인 미계산 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-291 | PQFixtureTest.test_unknown_signer | 미등록 서명자 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-292 | PQFixtureTest.test_algorithm_downgrade | 다운그레이드 거부 | 유지 | `ityv-crypto` | V2 |
| ITYV-BEH-293 | PQFixtureTest.test_wrong_keyset | 키 집합 불일치 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-294 | PQFixtureTest.test_missing_signature | 서명 누락 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-295 | PQFixtureTest.test_modified_signature | 서명 변조 거부 | 유지 | `ityv-crypto` | V1 |
| ITYV-BEH-296 | PQFixtureTest.test_external_anchor_diff | 외부 앵커 불일치 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-297 | PQFixtureTest.test_monitor_records_valid_head | 모니터가 유효 헤드 기록 | 유지 | 증인 도구 | V2 |
| ITYV-BEH-298 | PQFixtureTest.test_monitor_cannot_rollback_to_genesis | 모니터 되감기 불가 | 유지 | 증인 도구 | V2 |
| ITYV-BEH-299 | PQFixtureTest.test_monitor_cannot_accept_wrong_root | 모니터 잘못된 root 거부 | 유지 | 증인 도구 | V2 |
| ITYV-BEH-300 | PQFixtureTest.test_monitor_replay_is_idempotent | 모니터 재생 멱등 | 유지 | 증인 도구 | V2 |
| ITYV-BEH-301 | PQFixtureTest.test_monitor_fork_without_proof_fails | 증명 없는 분기 거부 | 유지 | 증인 도구 | V2 |

## 8. V9.1 기준정보·마감·보관·포함 (tests_v9_1)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-302 | test_01_original_fixture_genuine_pqc | 실제 서명 픽스처 검증 | 수정: KAT | `ityv-crypto` | V1 |
| ITYV-BEH-303 | test_02_out_of_band_roster_pin_wrong | 명단 핀 불일치 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-304 | test_03_genesis_pin_wrong | genesis 핀 불일치 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-305 | test_04_missing_genesis_pin | 핀 누락 거부 | 유지: 핀은 필수 인자 타입 | `ityv-verify` | V2 |
| ITYV-BEH-306 | test_05_genesis_quorum_8_13_denied | genesis 정족수 부족 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-307 | test_06_genesis_duplicate_signer_denied | genesis 중복 서명자 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-308 | test_07_change_genesis_expected_boxes_detected | 예상 투표함 변경 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-309 | test_08_genesis_bad_issuance_root_external_pin_detects | 발급 root 변조를 외부 핀이 탐지 | 수정: 명부 동결 commitment | `ityv-verify` | V2 |
| ITYV-BEH-310 | test_09_genesis_roster_swap_rejected | 명단 교체 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-311 | test_10_same_public_key_reused_in_two_device_ids_denied | 공개키 재사용 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-312 | test_11_duplicate_expected_box_denied | 투표함 중복 등록 거부 | 유지: 정렬·중복 없음 배열 | `ityv-encoding` | V2 |
| ITYV-BEH-313 | test_12_custody_route_orgs_collusion_not_accepted | 보관 경로 조직 독립성 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-314 | test_13_box_without_two_independent_orgs_denied | 독립 참관인 2 조직 미만 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-315 | test_14_wrong_election_close_rejected | 다른 선거 마감 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-316 | test_15_wrong_box_closing_attestation_rejected | 다른 투표함 마감 서명 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-317 | test_16_unsigned_count_change_rejected | 서명 없는 수량 변경 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-318 | test_17_physical_count_mismatch_rejected | 물리 수량 불일치 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-319 | test_18_device_signature_corrupted_rejected | 장치 서명 손상 거부 | 유지 | `ityv-crypto` | V1 |
| ITYV-BEH-320 | test_19_missing_second_observer_rejected | 두 번째 참관인 누락 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-321 | test_20_two_observers_one_organization_denied | 같은 조직 참관인 둘 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-322 | test_21_observer_can_not_reuse_signature_across_identifiers | 참관인 서명 교차 재사용 불가 | 유지 | `ityv-crypto` | V2 |
| ITYV-BEH-323 | test_22_observer_not_in_registered_roster | 미등록 참관인 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-324 | test_23_valid_box_close_2_orgs | 정상 2조직 마감 통과 | 유지 | `ityv-state` | V1 |
| ITYV-BEH-325 | test_24_custody_both_handoffs_real_signature | 인계 쌍방 실제 서명 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-326 | test_25_custody_step_removed_denied | 인계 단계 삭제 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-327 | test_26_custody_steps_reordered_denied | 인계 순서 변경 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-328 | test_27_custody_final_receiver_signature_changed_denied | 최종 수신 서명 변경 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-329 | test_28_custody_seal_change_denied | 봉인 변경 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-330 | test_29_custody_replayed_to_another_box_denied | 인계 교차 투표함 재생 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-331 | test_30_custody_inserting_handoff_denied | 인계 삽입 거부 | 유지 | `ityv-state` | V2 |
| ITYV-BEH-332 | test_31_crypto_evidence_coverage_holds_for_missing_paper_audit | 종이 감사 없으면 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-333 | test_32_paper_audit_self_assertion_not_legal_certification | 자기 주장 감사는 인증 아님 | 유지 | `ityv-verify` | V1 |
| ITYV-BEH-334 | test_33_missing_closed_box_holds | 마감 누락 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-335 | test_34_missing_custody_chain_holds | 보관 사슬 누락 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-336 | test_35_same_number_of_boxes_but_replaced_close_holds | 같은 수의 투표함이라도 마감 교체는 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-337 | test_36_global_ledger_omits_box_close | 장부의 마감 누락 탐지 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-338 | test_37_global_ledger_framed_record_corrupt | 프레임 손상 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-339 | test_38_pinned_external_root_rejects_rewritten_log | 외부 핀이 재작성 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-340 | test_39_checkpoint_same_log_but_omits_box_root | 마감 root 누락 체크포인트 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-341 | test_40_checkpoint_8_signers_rejected | 체크포인트 8 서명 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-342 | test_41_ledger_proof_for_different_root_holds | 다른 root 증명 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-343 | test_42_ledger_proof_for_different_election_holds | 다른 선거 증명 HOLD | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-344 | test_43_manifest_not_self_authenticated | 기준정보는 자기 인증되지 않는다 | 유지: 핀 필수 | `ityv-verify` | V2 |
| ITYV-BEH-345 | test_44_paper_origin_still_not_proven | 종이 원본 진정성은 암호로 증명되지 않는다 | 유지: 상태 어휘 | `ityv-verify` | V1 |
| ITYV-BEH-346 | test_45_refuses_fake_paper_audit_claim_in_fixture | 위조 감사 주장 거부 | 유지: 감사 이벤트는 서명 | `ityv-verify` | V2 |
| ITYV-BEH-347 | test_46_no_private_key_in_fixture | 픽스처에 비밀키 없음 | 폐기 D-DEMO | — | — |
| ITYV-BEH-348 | test_47_duplicate_json_fields_rejected | 중복 필드 거부 | 폐기 D-JSON | — | — |
| ITYV-BEH-349 | test_48_invalid_json_constants_rejected | 비정규 상수 거부 | 폐기 D-JSON | — | — |
| ITYV-BEH-350 | test_49_actual_global_log_contains_all_closes_and_custody | 장부가 모든 마감·인계를 포함 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-351 | test_50_ledger_contains_no_voter_choice_or_pii | 장부에 선택·개인정보 없음 | 유지 | `ityv-encoding` 스키마 | V2 |
| ITYV-BEH-352 | test_51_missing_out_of_band_log_anchor_pin_rejected | 앵커 핀 누락 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-353 | test_52_wrong_out_of_band_log_anchor_pin_rejected | 앵커 핀 불일치 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-354 | test_53_mutate_anchor_and_pin_together_does_not_match_real_chain | 앵커와 핀을 함께 바꿔도 실제 사슬과 불일치 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-355 | test_54_compromised_projection_restored_from_verified_log | 침해된 투영을 검증된 장부로 복원 | 유지 | `ityv-ledger` | V1 |
| ITYV-BEH-356 | test_55_attack_replace_source_log_with_new_chain_fails_old_anchor | 새 사슬로 교체해도 옛 앵커와 불일치 | 유지 | `ityv-verify` | V2 |

## 9. 로컬 랩 (local_lab/tests)

| ITYV ID | 원 테스트 | 불변식 | 적용 | 대상 | 단계 |
|---|---|---|---|---|---|
| ITYV-BEH-357 | LabSecurityTests.test_01_explicit_non_election_ack_required | 데모 실행 확인 필요 | 폐기 D-DEMO | — | — |
| ITYV-BEH-358 | LabSecurityTests.test_02_actual_ml_dsa_87_fixture | 실제 ML-DSA-87 픽스처 | 수정: KAT | `ityv-crypto` | V1 |
| ITYV-BEH-359 | LabSecurityTests.test_03_tampered_roster_pin_fails | 명단 핀 변조 실패 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-360 | LabSecurityTests.test_04_append_restart_and_duplicate | 추가·재시작·중복 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-361 | LabSecurityTests.test_05_framed_log_tamper_detected_on_restart | 재시작 시 변조 탐지 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-362 | LabSecurityTests.test_06_signed_fixture_is_separate_from_local_ledger | 픽스처와 로컬 장부 분리 | 폐기 D-DEMO | — | — |
| ITYV-BEH-363 | LabSecurityTests.test_07_mirror_accept_and_restart | 미러 수락·재시작 보존 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-364 | LabSecurityTests.test_08_mirror_rejects_rollback | 미러 되감기 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-365 | LabSecurityTests.test_09_mirror_rejects_same_length_fork | 같은 길이 분기 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-366 | LabSecurityTests.test_10_mirror_rejects_incorrect_anchor | 잘못된 앵커 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-367 | LabSecurityTests.test_11_mirror_rejects_false_independent_pin | 가짜 독립 핀 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-368 | LabSecurityTests.test_12_mirror_rejects_truncated_framed_leaf | 잘린 리프 거부 | 유지 | `ityv-ledger` | V2 |
| ITYV-BEH-369 | LabSecurityTests.test_13_mirror_rejects_corrupted_persisted_snapshot | 손상 스냅샷 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-370 | LabSecurityTests.test_14_ledger_http_auth_idempotency_and_conflict | HTTP 인증·멱등·충돌 | 폐기 D-COMPONENT(전송 계층은 TCB 밖, 멱등성은 ITYV-BEH-052) | — | — |
| ITYV-BEH-371 | LabSecurityTests.test_15_verifier_ui_has_strict_csp_and_no_mutating_api | 검증기 UI 보안 헤더 | 폐기 D-COMPONENT | — | — |
| ITYV-BEH-372 | LabSecurityTests.test_16_verifier_wrong_digest_same_length_rejected | 같은 길이 다른 digest 거부 | 유지 | `ityv-verify` | V2 |
| ITYV-BEH-373 | LabSecurityTests.test_17_kubernetes_requires_nonroot_and_closed_services | 배포 매니페스트 보안 | 폐기 D-COMPONENT(배포 계층은 별도 문서) | — | — |

## 10. 수확 규칙

- `유지`와 `수정` 행은 대상 크레이트의 속성 테스트, Kani 하네스, trybuild 컴파일 실패 테스트, 또는 시뮬레이터 시나리오로 구현되며 테스트 이름에 ITYV-BEH ID를 포함한다.
- `폐기` 행은 사유 코드와 함께 남겨 추적성을 유지한다.
- 같은 불변식을 여러 원 테스트가 검사한 경우 하나의 구현으로 합치되, 모든 ITYV-BEH ID를 그 구현의 문서 주석에 적는다.

## 11. `ityv-state` 대응 (M4, ADR-0025)

`ityv-state` 행이 어디서 증거를 얻는지 적는다. 경로는 `crates/ityv-state/` 기준이다. trybuild 대신 `compile_fail` doctest를 쓴다. "M5"·"M6"은 그 마일스톤으로 넘긴 행이다.

| 행 | 구현 | 비고 |
|---|---|---|
| 008, 161 | `status::evaluate`의 기본값 `UNVERIFIED`(`status::tests::default_is_unverified`, Kani `status_is_exact`) | |
| 017, 140, 141, 212, 279 | 훼손·오배송은 `PendingLegal`로 남고 기계 전이가 처분하지 않음, 미해결 분쟁은 `OpenDispute` 보류(`record`, `dispute`, Kani `record_machine`) | 분쟁·중복은 사건이지 무효가 아님 |
| 019, 151, 264, 324 | `tests/boxes.rs` `clean_life_cycle`(실제 하이브리드 서명의 마감, 인계, 개표, 감사) | |
| 023, 041, 043, 075, 091, 157, 158, 174, 175, 217, 270, 318 | `close::count_verdict`의 등식별 보류(`close::tests`, `tests/boxes.rs` `close_holds`, Kani `count_verdict_is_exact`, 속성 테스트) | 명세(§10.2)대로 거부가 아니라 수록 후 `HOLD_REVIEW` |
| 025, 082, 104, 220, 221, 266, 320, 321, 323 | `close::check_witnesses`(등록 여부, 중복 서명자, 사무원 2·서로 다른 조직 참관인 2) | |
| 026, 028, 034, 046, 048, 055, 084, 222 | `boxes` typestate와 `compile_fail` doctest(마감된 상자에 기록, 재개봉) | |
| 031, 080, 099, 172, 329 | 개시 `SealMismatch`, 인계 `CustodySealUnexplained`(`SealChange` 없을 때) | 명세(§10.3)대로 보류 |
| 033 | — | M5: 예고되지 않은 개함은 개시 일정 입력이 필요 |
| 035 | 어떤 판정도 시각을 입력으로 쓰지 않음(늦은 마감 기한만 구간 산술) | |
| 037, 081, 325, 328 | `custody` 양쪽 서명·수신자 연속성(`custody::tests::refusals`) | 서명 바이트 검증은 M5(스키마 0x0008) |
| 042, 092, 173 | `ImprintAudit` 보류(`tests/boxes.rs` `custody_and_counting_holds`), 참여 등식(`issuance`) | |
| 047, 100, 317 | 마감 장치 서명 토큰 결속(`tests/boxes.rs` `close_signature_binding`), 수동 마감 보류, 늦은 마감의 서명 요구 | |
| 063, 101 | `tests/proptests.rs` | |
| 077, 152, 170, 216 | `StatusReport::count_only` | |
| 083 | — | M5: 이벤트 색인 |
| 089 | — | 명세 공백(ADR-0025 공백 7) |
| 090 | `issuance::issuance_verdict`(Kani `issuance_verdict_is_exact`) | |
| 132, 133, 135, 136, 137, 138 | `dispute`(두 기관 접수, `OPEN`으로만 시작, 기술 해결 뒤 법적 회부), `LegalReference::from_signed` | |
| 150 | `PAPER_AUDITED`는 표본 대조 종료가 있어야 함(`status`) | |
| 162 | `Verified` 토큰과 `Authorization`의 비공개 생성자(시험용 생성자는 `cfg(test, kani)`) | 시뮬레이터 토큰 타입은 M6 |
| 165, 178 | `Status`에 `LEGAL_CERTIFIED` 없음(`compile_fail` doctest) | VC-049 |
| 171, 326, 327, 330, 331 | `custody`(순번, 이전 인계, 경로, 다른 상자), 인계 미완 개표 `CustodyIncomplete` | |
| 030 | — | M5: 카세트 이벤트(§10.5) |
| 267 | — | M5: 참관인 서명 검증 |
| 268, 269, 315, 316 | `Error::Mismatch`(다른 상자·선거의 개시·기록·마감·인계) | |
