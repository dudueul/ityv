//! Organisation names (`OrgId`) as the genesis rules compare them.
//!
//! An organisation identifier is ASCII letters, digits and `.`, `_`, `:`,
//! `-`. Two spellings of one name are one organisation: `MOIS-GPKI`,
//! `mois-gpki`, `MOIS_GPKI` and `MOISGPKI` name the same body, and a rule
//! that counts organisations (the custody quorum, the operators of the
//! timestamp authorities) or keeps them apart (an operator is no witness
//! and no election commission) must not count it twice or let it through
//! under another spelling. So names are compared with letters lowered and
//! the separators dropped (ADR-0039 2, ADR-0040).

use ityv_encoding::OrgId;

/// Whether `byte` is a separator a name may be written with or without.
const fn separator(byte: u8) -> bool {
    matches!(byte, b'.' | b'_' | b':' | b'-')
}

/// The bytes of `org` that name it: separators dropped, letters lowered.
fn significant(org: &[u8]) -> impl Iterator<Item = u8> + '_ {
    org.iter()
        .copied()
        .filter(|b| !separator(*b))
        .map(|b| b.to_ascii_lowercase())
}

/// Whether `a` and `b` name one organisation.
pub(crate) fn same_org(a: OrgId<'_>, b: OrgId<'_>) -> bool {
    significant(a.as_bytes()).eq(significant(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use ityv_encoding::OrgId;

    use super::same_org;

    fn org(b: &'static [u8]) -> OrgId<'static> {
        OrgId::new(b).unwrap()
    }

    #[test]
    fn spellings_of_one_name_are_one_organisation() {
        for other in [
            b"MOIS-GPKI".as_slice(),
            b"mois-gpki",
            b"Mois-Gpki",
            b"MOIS_GPKI",
            b"MOIS.GPKI",
            b"MOIS:GPKI",
            b"MOISGPKI",
            b"-M-O-I-S-G-P-K-I-",
        ] {
            assert!(same_org(org(b"MOIS-GPKI"), org(other)), "{other:?}");
            assert!(same_org(org(other), org(b"MOIS-GPKI")), "{other:?}");
        }
    }

    #[test]
    fn other_letters_or_digits_are_another_organisation() {
        for other in [
            b"MOIS-GPKI2".as_slice(),
            b"MOIS-GPK",
            b"OIS-GPKI",
            b"MOIS-GPKJ",
            b"NOIS-GPKI",
            b"M0IS-GPKI",
        ] {
            assert!(!same_org(org(b"MOIS-GPKI"), org(other)), "{other:?}");
            assert!(!same_org(org(other), org(b"MOIS-GPKI")), "{other:?}");
        }
        assert!(same_org(org(b"A1"), org(b"a1")));
        assert!(!same_org(org(b"A1"), org(b"A2")));
    }
}
