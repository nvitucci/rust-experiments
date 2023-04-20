//! Implementation of the DSA algorithm

use super::*;

pub struct DSA {
    /// Public prime
    pub p: BigUint,
    /// Public group order
    pub q: BigUint,
    /// Public group generator
    pub g: BigUint,
    /// Public value _g_<sup>_x_</sup> mod _p_
    pub y: BigUint,
    /// Secret exponent
    pub x: BigUint,
}

/// Use the DSA algorithm to sign messages and verify signatures
impl Sign for DSA {
    /// Simple method that converts the BigUint `m` to a string, computes its
    /// SHA256 hash, then converts the hash to a BigUint
    fn hash(m: &BigUint) -> BigUint {
        let h = digest(m.to_string());

        BigUint::parse_bytes(h.as_bytes(), 16).expect("Cannot convert bytes to BigUint")
    }

    /// Produce the signature (_r_, _s_) with
    ///
    /// _r_ = (_g_<sup>_k_</sup> mod _p_) mod _q_
    ///
    /// _s_ = _k_<sup>-1</sup> (hash(_`m`_) + _x_ * _r_) mod _q_
    ///
    /// (where 0 < _k_ < _q_ is randomly generated)
    fn sign(&self, m: &BigUint) -> Signature {
        // Generate a random k between 1 and q-1
        let k = random_bignum(&BigUint::from(1u32), &self.q);
        // By Fermat's little theorem, k^-1 mod q == k^(q-2) mod q
        let k_inv = k.modpow(&(&self.q - BigUint::from(2u32)), &self.q);

        let r = self.g.modpow(&k, &self.p) % &self.q;
        let s = (k_inv * (Self::hash(m) + &self.x * &r)) % &self.q;

        Signature::Pair(r, s)
    }

    /// From the signature `sig` = (_r_, _s_) compute:
    ///
    /// _u_<sub>1</sub> = (hash(_`m`_) * _s_<sup>-1</sup>) mod _q_
    ///
    /// _u_<sub>2</sub> = _r_ * _w_ mod _q_
    ///
    /// then compute _v_ = (_g_<sup>_u_<sub>1</sub></sup> * _y_<sup>_u_<sub>2</sub></sup> mod _p_) mod _q_
    ///
    /// and verify that _v_ == _r_.
    fn verify(&self, m: &BigUint, sig: &Signature) -> bool {
        match sig {
            Signature::Pair(r, s) => {
                let s_inv = s.modpow(&(&self.q - BigUint::from(2u32)), &self.q);
                let u1 = (Self::hash(m) * &s_inv) % &self.q;
                let u2 = (r * s_inv) % &self.q;

                let v =
                    (self.g.modpow(&u1, &self.p) * self.y.modpow(&u2, &self.p)) % &self.p % &self.q;

                &v == r
            }
            _ => panic!("Not a pair"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bignum;

    #[test]
    fn test_dsa_small() {
        // Numbers from the HAC book
        let dsa = DSA {
            p: BigUint::from(124540019u32),
            q: BigUint::from(17389u32),
            g: BigUint::from(10083255u32),
            y: BigUint::from(119946265u32),
            x: BigUint::from(12496u32),
        };

        let m = BigUint::from(124540019u32);

        let signed = dsa.sign(&m);
        let verified = dsa.verify(&m, &signed);

        assert!(verified);
    }

    #[test]
    fn test_dsa() {
        let dsa = DSA {
            p: bignum(b"18930220156430884707787581982667150040342430340581318144882873819932152076526785030251961196398351578194563868897190745374095251758424394261360805168806460656249703469940687759082462743640271637412219269681401266486363162406314424074519524348194521871456736447930149129093028417492206038678352211028807489939631756679248824839474394219858960509462855844515569789236313673678209369715806185856617488908074193110315943719105318695451712919337304296824652370502454793202621451876158511543613732739890414338549063471771127063877203894361662918416870845455155949361366086822291655022313839293705976131720601764349138188763"),
            q: bignum(b"77329472688943863782809684314309611412099174806793669931856388423150706393447"),
            g: bignum(b"9776352536598101331432253534187162046797971077269626288014571662233110493164650880686970679823027823782693979916732176955913010538621389580201197451835850449349401498615800410766032380854611786555966853817267325239512000930084764892283051664768149497273193030000400930558709969898151798576730413946075652301924503319572711955695693129578328117269721696248195211019503146843488075633287525582407824111700730431268482972630743457867358536579474264670693432213201731134512477024166751325249293155566771418339122598660995442996355382603925473715661262608962598234427508654831621526829645072886787047595607539558463000444"),
            y: bignum(b"10724392575130207156071095265641597303485892984432677155198160243874833612494142949396125374542186243165624569971691773432654567439240367909706445219719828407566860880184150096675886463333075597901899438944411768285518047404374844574637379248883947243547127317112321816149952128981946891128067470332020385770766406208444905612330088021679921652404504950961006753477156457704784219178166816133076168833926154370406480664919715566381132438484472750743002339128065378009284094527365506266826999182633125457061276960366686790260766865762855660374392088920250978820732228600679753002316993258157710832553602657970334455236"),
            x: bignum(b"67280696483525608869730051502255070481129155564254771476611158635103194927878"),
        };

        let m = bignum(b"1482726341215123");

        let signed = dsa.sign(&m);
        let verified = dsa.verify(&m, &signed);

        assert!(verified);
    }

    #[test]
    fn test_dsa_hash() {
        assert_eq!(
            DSA::hash(&bignum(b"2")),
            bignum(
                b"96094161643976066833367867971426158458230048495430276217795328666133331159861"
            )
        );
    }
}
