//! This module provides functions to work with DAPS certificates.

type SkiAkiPrivateKey<'a> = (std::borrow::Cow<'a, str>, std::borrow::Cow<'a, [u8]>);

/// Reads a .p12 from file, extracts the certificate and returns the SKI:AKI
pub fn ski_aki_and_private_key_from_file<'a>(
    p12_file_path: &std::path::Path,
    password: &str,
) -> Result<SkiAkiPrivateKey<'a>, Box<dyn std::error::Error>> {
    use std::io::Read;

    // Read the .p12 file
    let mut file = std::fs::File::open(p12_file_path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    // Read in the .p12 file and parse it
    let pkcs12 = openssl::pkcs12::Pkcs12::from_der(buf.as_slice())?;
    let parsed_pkcs12 = pkcs12.parse2(password)?;

    // Extract the SKI:AKI from the certificate
    let ski_aki_str = ski_aki(
        &parsed_pkcs12
            .cert
            .ok_or("Certificate not found in .p12 file")?,
    )?;
    // Extract the private key
    let private_key_der = parsed_pkcs12
        .pkey
        .ok_or("Private key not found in .p12 file")?
        .private_key_to_der()?;

    Ok((ski_aki_str, std::borrow::Cow::from(private_key_der)))
}

/**
 * Extracts the *Subject Key Identifier* and *Authority Key Identifier* from a certificate and creates
 * a String of the form "`SKI:keyid:AKI`", where SKI and AKI are the hex-encoded values of the
 * Subject Key Identifier* and *Authority Key Identifier*, respectively.
 */
pub fn ski_aki<'a>(
    x509: &openssl::x509::X509,
) -> Result<std::borrow::Cow<'a, str>, Box<dyn std::error::Error>> {
    let ski = x509
        .subject_key_id()
        .expect("SKI is required to exist in Certificate")
        .as_slice()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<String>>()
        .join(":");

    let aki = x509
        .authority_key_id()
        .expect("AKI is required to exist in Certificate")
        .as_slice()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<String>>()
        .join(":");

    Ok(std::borrow::Cow::from([ski, aki].join(":keyid:")))
}

#[cfg(test)]
mod test {
    use super::*;

    /// Loads a certificate and extracts the SKI:AKI
    #[test]
    fn test_ski_aki() {
        let ski_aki = ski_aki_and_private_key_from_file(
            std::path::Path::new("./testdata/connector-certificate.p12"),
            "Password1",
        )
        .expect("Reading SKI:AKI failed");
        assert_eq!(ski_aki.0, "65:55:CE:32:79:B4:1A:BD:23:91:D1:27:4A:CE:05:BC:0A:D9:92:E5:keyid:65:55:CE:32:79:B4:1A:BD:23:91:D1:27:4A:CE:05:BC:0A:D9:92:E5");
    }
}
