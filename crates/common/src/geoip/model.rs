use smol_str::SmolStr;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct LocationAndIsp {
    pub autonomous_system_number: Option<u32>,
    pub autonomous_system_organization: Option<SmolStr>,
    pub isp: Option<SmolStr>,
    pub organization: Option<SmolStr>,

    pub city: Option<model::City>,
    pub continent: Option<model::Continent>,
    pub country: Option<model::Country>,
    pub location: Option<model::Location>,
}

pub mod model {
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
    use smol_str::SmolStr;

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Country {
        pub is_in_european_union: Option<bool>,
        pub iso_code: Option<SmolStr>,
        pub names: Option<EnglishName>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Location {
        pub latitude: Option<f64>,
        pub longitude: Option<f64>,
        // pub time_zone: Option<SmolStr>,
        // pub weather_code: Option<SmolStr>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Postal {
        pub code: Option<SmolStr>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Continent {
        pub code: Option<SmolStr>,
        pub names: Option<EnglishName>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct City {
        pub geoname_id: Option<u32>,
        pub names: Option<EnglishName>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct EnglishName {
        pub en: Option<SmolStr>,
    }

    #[derive(Deserialize, Serialize, Clone, Debug)]
    pub struct Subdivision {
        pub geoname_id: Option<u32>,
        pub names: Option<EnglishName>,
    }

    #[derive(Clone, Debug)]
    pub enum ConnectionType {
        Dialup,
        Isdn,
        Cable,
        Dsl,
        Fttx,
        Wireless,
    }

    impl Serialize for ConnectionType {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(match *self {
                ConnectionType::Dialup => "dialup",
                ConnectionType::Isdn => "isdn",
                ConnectionType::Cable => "cable",
                ConnectionType::Dsl => "dsl",
                ConnectionType::Fttx => "fttx",
                ConnectionType::Wireless => "wireless",
            })
        }
    }

    impl<'de> Deserialize<'de> for ConnectionType {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = SmolStr::deserialize(deserializer)?;
            match s.as_str() {
                "dialup" => Ok(ConnectionType::Dialup),
                "isdn" => Ok(ConnectionType::Isdn),
                "cable" => Ok(ConnectionType::Cable),
                "dsl" => Ok(ConnectionType::Dsl),
                "fttx" => Ok(ConnectionType::Fttx),
                "wireless" => Ok(ConnectionType::Wireless),
                _ => Err(de::Error::custom("unknown connection_type")),
            }
        }
    }
}
