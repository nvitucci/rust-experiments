//! Implementation of the Elgamal algorithm

use super::*;

pub struct ElGamal {
    /// Public prime
    pub p: BigUint,
    /// Public group generator
    pub g: BigUint,
    /// Public value _g_<sup>_x_</sup> mod _p_
    pub y: BigUint,
    /// Secret exponent
    pub x: BigUint,
}

impl Encrypt for ElGamal {
    /// Compute the ciphertext (_c_<sub>1</sub>, _c_<sub>2</sub>) with
    ///
    /// _c_<sub>1</sub> = _g_<sup>_k_</sup> mod _p_
    ///
    /// _c_<sub>2</sub> = _`m`_ * _s_ mod _p_
    ///
    /// (where 0 < _k_ < _p_ - 1 is randomly generated and _s_ =  _y_<sup>_k_</sup> is the _shared secret_)
    fn encrypt(&self, m: &BigUint) -> Ciphertext {
        // Generate a random k between 1 and p-1
        let k = random_bignum(&BigUint::from(1u32), &(&self.p - BigUint::from(1u32)));
        let s = self.y.modpow(&k, &self.p); // shared secret s

        let c1 = self.g.modpow(&k, &self.p);
        let c2 = (m * s) % &self.p;

        Ciphertext::Pair(c1, c2)
    }

    /// From the ciphertext (_c_<sub>1</sub>, _c_<sub>2</sub>) compute
    ///
    /// _s_<sup>-1</sup> = (_y_<sup>_k_</sup>)<sup>-1</sup> = ((_g_<sup>_x_</sup>)<sup>_k_</sup>)<sup>-1</sup> = _c_<sub>1</sub><sup>-_x_</sup> = _c_<sub>1</sub><sup>_p_ - 1 - _x_</sup> mod _p_
    ///
    /// and retrieve the original message
    ///
    /// _m_ = _s_<sup>-1</sup> * _c_<sub>2</sub> mod _p_
    fn decrypt(&self, c: &Ciphertext) -> BigUint {
        match c {
            Ciphertext::Pair(c1, c2) => {
                // Compute the inverse of the shared secret s
                let s_inv = c1.modpow(&(&self.p - BigUint::from(1u32) - &self.x), &self.p);
                let m = (c2 * s_inv) % &self.p;

                m
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
    fn test_elgamal_small() {
        // Numbers from the HAC book
        let elgamal = ElGamal {
            p: BigUint::from(2357u32),
            g: BigUint::from(2u32),
            y: BigUint::from(1185u32),
            x: BigUint::from(1751u32),
        };

        let m = BigUint::from(2035u32);

        let encrypted = elgamal.encrypt(&m);
        let decrypted = elgamal.decrypt(&encrypted);

        assert_eq!(m, decrypted);
    }

    #[test]
    fn test_elgamal() {
        let elgamal = ElGamal {
            p: bignum(b"21184795224212536964062883050432832896219180043306745749507173456191006787311146854668821513315952228690166108340246881055280083954021140230360109139210549183430005605616829049480465189085545832479727332745387886538641769815794752311817699632294459913736902844395790405051970352731077204037998783513130589208851997845158638472072468616025046402553224295502860056712883342790113689935316985246818793713930252667398829988405042143167096182757216513627895445171115572143858787433983678864090060986677504505167265543059226905114937436266049720413372897671084091167754147649933819526873415745134475534382738086734552688143"),
            g: bignum(b"5"),
            y: bignum(b"19807665444265041657990177107385033349747839926670669671385346779887167874349638280822801372810919990395863498154790640244438754036977740163782735915326218215020732086291478236345235716255836603410188555847043334823639271225009503959675200461464217135020809968239213787524669134970143391638737520877381736741234294852676687654189217772756223053069824285066683179699040712719155241983138335681604882270920880707772542759415275782192139967872091314569380301748781104585325131212122744030265022966524566056609327022825696274689322286018817050110030541738742416397112862361974086701732959305990984850610177647733174357595"),
            x: bignum(b"1270742310900726690413026462488924015958858380202122408190957963265926396562890535592476096127516928825")
        };

        let m = bignum(b"1482726341215123");

        let encrypted = elgamal.encrypt(&m);
        let decrypted = elgamal.decrypt(&encrypted);

        assert_eq!(m, decrypted);
    }
}
