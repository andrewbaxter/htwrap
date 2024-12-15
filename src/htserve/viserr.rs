use {
    std::fmt::Display,
};

/// An error type differentiated between being customer-facing or internal (with
/// internal details).
pub enum VisErr<E> {
    Internal(E),
    External(String),
}

pub trait ResultVisErr<O, E> {
    fn err_internal(self) -> Result<O, VisErr<E>>;
    fn err_external(self) -> Result<O, VisErr<E>>;
}

impl<O, E, F: Into<E> + Display> ResultVisErr<O, E> for Result<O, F> {
    fn err_internal(self) -> Result<O, VisErr<E>> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(VisErr::Internal(e.into())),
        }
    }

    fn err_external(self) -> Result<O, VisErr<E>> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(VisErr::External(e.to_string())),
        }
    }
}
