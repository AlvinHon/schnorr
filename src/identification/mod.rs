pub mod dl;

pub mod ec;

pub type Identification<H, S> = dl::Identification<H, S>;
pub type IdentificationECP256<H, S> = ec::Identification<H, S>;
