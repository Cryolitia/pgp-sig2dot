use log::{trace, warn};
use std::fmt::Display;

pub trait SuppressErrors<T, E>
where
    E: Display,
{
    /// Maps the `Ok` value to a new type, or warn the `Err` value.
    fn map_or_warn<F: FnOnce(T)>(self, err_prefix: &str, f: F);

    /// Returns the `Ok` value or warns the `Err` value.
    fn or_warn(self, err_prefix: &str) -> Option<T>;
}

impl<T, E> SuppressErrors<T, E> for Result<T, E>
where
    E: Display,
{
    /// Maps the `Ok` value to a new type, or warn the `Err` value.
    fn map_or_warn<F: FnOnce(T)>(self, err_prefix: &str, f: F) {
        match self {
            Ok(t) => f(t),
            Err(e) => {
                warn!("{err_prefix}: {:#}", e);
            }
        }
    }

    fn or_warn(self, err_prefix: &str) -> Option<T> {
        match self {
            Ok(t) => Some(t),
            Err(e) => {
                warn!("{err_prefix}: {:#}", e);
                None
            }
        }
    }
}

pub trait SuppressPrint<T, E>
where
    T: Display,
    E: Display,
{
    /// Prints the `Ok` value, or warn the `Err` value.
    fn print_or_warn(self, err_prefix: &str);
}

impl<T, E> SuppressPrint<T, E> for Result<T, E>
where
    T: Display,
    E: Display,
{
    fn print_or_warn(self, err_prefix: &str) {
        match self {
            Ok(t) => {
                println!("{t}");
            }
            Err(e) => {
                warn!("{err_prefix}: {:#}", e);
            }
        }
    }
}

pub trait SuppressResultErrors<T1, T2, E1, E2> {
    fn map_and_warn_result<F: FnOnce(T1) -> Result<T2, E2>>(self, err_prefix: &str, f: F);
}

impl<T1, T2, E1, E2> SuppressResultErrors<T1, T2, E1, E2> for Result<T1, E1>
where
    E1: Display,
    E2: Display,
{
    /// Maps the `Ok` value to a new type, or warn the `Err` value.
    fn map_and_warn_result<F: FnOnce(T1) -> Result<T2, E2>>(self, err_prefix: &str, f: F) {
        match self {
            Ok(t) => {
                f(t).map_err(|e| warn!("{err_prefix}: {:#}", e)).ok();
            }
            Err(e) => {
                warn!("{err_prefix}: {:#}", e);
            }
        }
    }
}

impl<T1, T2, E> SuppressResultErrors<T1, T2, String, E> for Option<T1>
where
    E: Display,
{
    /// Maps the `Ok` value to a new type, or warn the `Err` value.
    fn map_and_warn_result<F: FnOnce(T1) -> Result<T2, E>>(self, err_prefix: &str, f: F) {
        if let Some(t) = self {
            f(t).map_err(|e| warn!("{err_prefix}: {:#}", e)).ok();
        }
    }
}

pub trait SuppressResultOk<T1, T2, E1, E2> {
    fn ok_or_warn<F: FnOnce(T1) -> Result<T2, E2>>(self, err_prefix: &str, f: F) -> Option<T2>;
}

impl<T1, T2, E1, E2> SuppressResultOk<T1, T2, E1, E2> for Result<T1, E1>
where
    E1: Display,
    E2: Display,
{
    /// Maps the `Ok` value to a new type, or warn the `Err` value.
    fn ok_or_warn<F: FnOnce(T1) -> Result<T2, E2>>(self, err_prefix: &str, f: F) -> Option<T2> {
        match self {
            Ok(t) => f(t).map_err(|e| warn!("{err_prefix}: {:#}", e)).ok(),
            Err(e) => {
                warn!("{err_prefix}: {:#}", e);
                None
            }
        }
    }
}

pub trait SuppressResultOkOrDefault<T1, T2, E>
where
    T2: Default,
{
    fn ok_or_warn_default<F: FnOnce(T1) -> Result<T2, E>>(self, err_prefix: &str, f: F) -> T2;
}

impl<T1, T2, E1, E2> SuppressResultOkOrDefault<T1, T2, E2> for Result<T1, E1>
where
    T2: Default,
    E1: Display,
    E2: Display,
{
    /// Maps the `Ok` value to a new type, or warn the `Err` value.
    fn ok_or_warn_default<F: FnOnce(T1) -> Result<T2, E2>>(self, err_prefix: &str, f: F) -> T2 {
        match self {
            Ok(t) => f(t).unwrap_or_else(|e| {
                warn!("{err_prefix}: {:#}", e);
                Default::default()
            }),
            Err(e) => {
                warn!("{err_prefix}: {:#}", e);
                Default::default()
            }
        }
    }
}

impl<T1, T2, E1, E2> SuppressResultOkOrDefault<T1, T2, E2> for Result<Option<T1>, E1>
where
    T2: Default,
    E1: Display,
    E2: Display,
{
    /// Maps the `Ok` value to a new type, or warn the `Err` value.
    fn ok_or_warn_default<F: FnOnce(T1) -> Result<T2, E2>>(self, err_prefix: &str, f: F) -> T2 {
        match self {
            Ok(t) => match t {
                Some(u) => f(u).unwrap_or_else(|e| {
                    warn!("{err_prefix}: {:#}", e);
                    Default::default()
                }),
                None => {
                    trace!("{err_prefix}: None value encountered");
                    Default::default()
                }
            },
            Err(e) => {
                warn!("{err_prefix}: {:#}", e);
                Default::default()
            }
        }
    }
}

impl<T1, T2, E> SuppressResultOkOrDefault<T1, T2, E> for Option<T1>
where
    T2: Default,
    E: Display,
{
    /// Maps the `Some` value to a new type, or warn the `None` value.
    fn ok_or_warn_default<F: FnOnce(T1) -> Result<T2, E>>(self, err_prefix: &str, f: F) -> T2 {
        match self {
            Some(u) => f(u).unwrap_or_else(|e| {
                warn!("{err_prefix}: {:#}", e);
                Default::default()
            }),
            None => {
                trace!("{err_prefix}: None value encountered");
                Default::default()
            }
        }
    }
}
