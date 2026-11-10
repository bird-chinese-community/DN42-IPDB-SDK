use dn42_ipdb::Bundle;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let directory = arguments
        .next()
        .ok_or("usage: lookup BUNDLE_DIRECTORY IP")?;
    let ip = arguments
        .next()
        .ok_or("usage: lookup BUNDLE_DIRECTORY IP")?
        .parse()?;
    let bundle = Bundle::open(directory)?;
    println!("{:?}", bundle.lookup_ip(ip)?);
    Ok(())
}
