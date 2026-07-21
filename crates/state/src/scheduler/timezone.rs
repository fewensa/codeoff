use chrono::{
  Datelike, FixedOffset, MappedLocalTime, NaiveDate, NaiveDateTime, Offset as ChronoOffset,
  TimeZone as ChronoTimeZone, Timelike,
};
use jiff::{
  Timestamp,
  civil::DateTime as CivilDateTime,
  tz::{AmbiguousOffset, TimeZone, TimeZoneDatabase},
};

const REQUIRED_TZDB_VERSION: &str = "2026c";

#[derive(Clone, Debug)]
pub(super) struct BundledTimeZone {
  timezone: TimeZone,
}

#[derive(Clone, Debug)]
pub(super) struct BundledOffset {
  fixed: FixedOffset,
  timezone: TimeZone,
}

impl BundledTimeZone {
  pub(super) fn parse(name: &str) -> Result<Self, ()> {
    if jiff_tzdb::VERSION != Some(REQUIRED_TZDB_VERSION) {
      return Err(());
    }
    TimeZoneDatabase::bundled()
      .get(name)
      .map(|timezone| Self { timezone })
      .map_err(|_| ())
  }

  pub(super) fn canonical_name(&self) -> Option<&str> {
    self.timezone.iana_name()
  }

  fn local_offset(&self, local: &NaiveDateTime) -> MappedLocalTime<BundledOffset> {
    let Ok(local) = to_civil(local) else {
      return MappedLocalTime::None;
    };
    match self.timezone.to_ambiguous_timestamp(local).offset() {
      AmbiguousOffset::Unambiguous { offset } => {
        MappedLocalTime::Single(self.offset(offset.seconds()))
      }
      AmbiguousOffset::Gap { .. } => MappedLocalTime::None,
      AmbiguousOffset::Fold { before, after } => {
        MappedLocalTime::Ambiguous(self.offset(before.seconds()), self.offset(after.seconds()))
      }
    }
  }

  fn offset(&self, seconds: i32) -> BundledOffset {
    BundledOffset {
      fixed: FixedOffset::east_opt(seconds).expect("IANA offset must fit chrono FixedOffset"),
      timezone: self.timezone.clone(),
    }
  }

  fn utc_offset(&self, utc: &NaiveDateTime) -> BundledOffset {
    let timestamp = Timestamp::from_second(utc.and_utc().timestamp())
      .expect("scheduler cron timestamps must fit the bundled Jiff range");
    self.offset(self.timezone.to_offset(timestamp).seconds())
  }
}

impl ChronoOffset for BundledOffset {
  fn fix(&self) -> FixedOffset {
    self.fixed
  }
}

impl ChronoTimeZone for BundledTimeZone {
  type Offset = BundledOffset;

  fn from_offset(offset: &Self::Offset) -> Self {
    Self {
      timezone: offset.timezone.clone(),
    }
  }

  fn offset_from_local_date(&self, local: &NaiveDate) -> MappedLocalTime<Self::Offset> {
    local
      .and_hms_opt(0, 0, 0)
      .map_or(MappedLocalTime::None, |local| self.local_offset(&local))
  }

  fn offset_from_local_datetime(&self, local: &NaiveDateTime) -> MappedLocalTime<Self::Offset> {
    self.local_offset(local)
  }

  fn offset_from_utc_date(&self, utc: &NaiveDate) -> Self::Offset {
    self.utc_offset(&utc.and_hms_opt(0, 0, 0).expect("midnight must be valid"))
  }

  fn offset_from_utc_datetime(&self, utc: &NaiveDateTime) -> Self::Offset {
    self.utc_offset(utc)
  }
}

fn to_civil(datetime: &NaiveDateTime) -> Result<CivilDateTime, ()> {
  CivilDateTime::new(
    i16::try_from(datetime.year()).map_err(|_| ())?,
    i8::try_from(datetime.month()).map_err(|_| ())?,
    i8::try_from(datetime.day()).map_err(|_| ())?,
    i8::try_from(datetime.hour()).map_err(|_| ())?,
    i8::try_from(datetime.minute()).map_err(|_| ())?,
    i8::try_from(datetime.second()).map_err(|_| ())?,
    i32::try_from(datetime.nanosecond()).map_err(|_| ())?,
  )
  .map_err(|_| ())
}

#[cfg(test)]
mod tests {
  use chrono::{MappedLocalTime, NaiveDate, Offset as _, TimeZone as _};
  use jiff::{civil::date, tz::AmbiguousOffset};

  use super::{BundledTimeZone, REQUIRED_TZDB_VERSION};

  #[test]
  fn test_adapter_uses_required_bundled_tzdb_and_matches_jiff_resolution() {
    assert_eq!(jiff_tzdb::VERSION, Some(REQUIRED_TZDB_VERSION));
    let adapter = BundledTimeZone::parse("America/Edmonton").expect("bundled Alberta zone");
    let local = NaiveDate::from_ymd_opt(2026, 3, 8)
      .expect("date")
      .and_hms_opt(2, 30, 0)
      .expect("time");
    assert!(matches!(
      adapter.offset_from_local_datetime(&local),
      MappedLocalTime::None
    ));

    let direct = adapter
      .timezone
      .to_ambiguous_timestamp(date(2026, 3, 8).at(2, 30, 0, 0))
      .offset();
    assert!(matches!(direct, AmbiguousOffset::Gap { .. }));

    let permanent_offset = NaiveDate::from_ymd_opt(2026, 11, 1)
      .expect("date")
      .and_hms_opt(1, 30, 0)
      .expect("time");
    let MappedLocalTime::Single(offset) = adapter.offset_from_local_datetime(&permanent_offset)
    else {
      panic!("2026c Alberta permanent UTC-06 must remove the former fall fold");
    };
    assert_eq!(offset.fix().local_minus_utc(), -6 * 60 * 60);
    let direct = adapter
      .timezone
      .to_ambiguous_timestamp(date(2026, 11, 1).at(1, 30, 0, 0))
      .offset();
    assert!(matches!(
      direct,
      AmbiguousOffset::Unambiguous { offset } if offset.seconds() == -6 * 60 * 60
    ));
  }
}
