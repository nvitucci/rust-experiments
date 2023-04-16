//! Implementation of the RSA algorithm

use super::*;

pub struct RSA {
    /// Public modulus
    pub n: BigUint,
    /// Public exponent
    pub e: BigUint,
    /// Secret exponent
    pub d: BigUint,
}

/// Use the RSA algorithm to encrypt and decrypt messages
impl Encrypt for RSA {
    /// Compute _`m`_<sup>_e_</sup> mod _n_
    fn encrypt(&self, m: &BigUint) -> Ciphertext {
        Ciphertext::Single(m.modpow(&self.e, &self.n))
    }

    /// Compute _`c`_<sup>_d_</sup> mod _n_
    fn decrypt(&self, c: &Ciphertext) -> BigUint {
        match c {
            Ciphertext::Single(c) => c.modpow(&self.d, &self.n),
            _ => panic!("Not a single value"),
        }
    }
}

/// Use the RSA algorithm to sign messages and verify signatures
impl Sign for RSA {
    /// Simple method that converts the BigUint `m` to a string, computes its
    /// SHA256 hash, then converts the hash to a BigUint
    fn hash(m: &BigUint) -> BigUint {
        let h = digest(m.to_string());

        BigUint::parse_bytes(h.as_bytes(), 16).expect("Cannot convert bytes to BigUint")
    }

    /// Produce the signature hash(_`m`_)<sup>_d_</sup> mod _n_
    fn sign(&self, m: &BigUint) -> Signature {
        Signature::Single(Self::hash(m).modpow(&self.d, &self.n))
    }

    /// Compute _`sig`_<sup>_e_</sup> mod _n_ and compare to hash(_`m`_)
    fn verify(&self, m: &BigUint, sig: &Signature) -> bool {
        match sig {
            Signature::Single(s) => s.modpow(&self.e, &self.n) == Self::hash(m),
            _ => panic!("Not a single value"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bignum;

    #[test]
    fn test_rsa_small() {
        // Numbers from the HAC book
        let rsa = RSA {
            n: BigUint::from(2357u32) * BigUint::from(2551u32),
            e: BigUint::from(3674911u32),
            d: BigUint::from(422191u32),
        };

        let m = BigUint::from(5234673u32);

        let rsa_encoded = rsa.encrypt(&m);
        let rsa_decoded = rsa.decrypt(&rsa_encoded);

        assert_eq!(m, rsa_decoded);
    }

    #[test]
    fn test_rsa() {
        let rsa = RSA {
            n: bignum(b"24285567456616572535053163704040517696339053520634523513959490724007229796719740152317361083535903559526887151910583738749192724073752114685883652689425560188238375621459958617205457390994531647966048552252431253837715142607154249583275263403961793022725225708928576824094708202567623969946919484541872521257547449677583916437272177792287910013177936025088702170345854171069059816126279489604018885163082286699535072424228488832207776143066543758831629156184365560217187829162278060910799742497812823133120175704776511913669284170673753127829411572441993508065373965371003598177072369409326086217971424873326320403767"),
            e: bignum(b"65537"),
            d: bignum(b"4246648504704608408253494301666300453179815269946314897996181755300408219332716208333566657267214776266507877395902919664704649554987247422070382529270746597452000925003145181396379780899298605149624126963590981719947747597204444820854395511076218747279110832420182345913382608319345876307913045956480447588505904098748546621165568873421092788829173712507771720454061237012649434229751644062202815204041718422716997993742509002869211664920269003099439680742846774758669152760830688242344700050431906885674769163678723468025888796520771344968669620518651547899167951600305545613239608787193640741107853748457567524673")
        };

        let m = bignum(b"1482726341215123");

        let rsa_encoded = rsa.encrypt(&m);
        let rsa_decoded = rsa.decrypt(&rsa_encoded);

        assert_eq!(m, rsa_decoded);
    }
}
