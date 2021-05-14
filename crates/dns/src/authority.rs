use futures::TryFutureExt;
use parking_lot::RwLock;
use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc};
use trust_dns_server::{
    authority::{BoxedLookupFuture, LookupError, LookupObject},
    client::{op::LowerQuery, rr::LowerName},
    proto::rr::{dnssec::SupportedAlgorithms, RecordType},
};

/// An Object safe Authority
pub trait AuthorityObject: Send + Sync {
    /// Clone the object
    fn box_clone(&self) -> Box<dyn AuthorityObject>;

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> LowerName;

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> BoxedLookupFuture;

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vectory containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> BoxedLookupFuture;

    /// Get the NS, NameServer, record for the zone
    fn ns(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> BoxedLookupFuture {
        self.lookup(
            &self.origin(),
            RecordType::NS,
            is_secure,
            supported_algorithms,
            src,
        )
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    fn get_nsec_records(
        &self,
        name: &LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture;

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    fn soa(&self, src: IpAddr) -> BoxedLookupFuture {
        // SOA should be origin|SOA
        self.lookup(
            &self.origin(),
            RecordType::SOA,
            false,
            SupportedAlgorithms::new(),
            src,
        )
    }

    /// Returns the SOA record for the zone
    fn soa_secure(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> BoxedLookupFuture {
        self.lookup(
            &self.origin(),
            RecordType::SOA,
            is_secure,
            supported_algorithms,
            src,
        )
    }
}

/// Authority implementations can be used with a `Catalog`
pub trait Authority: Send {
    /// Result of a lookup
    type Lookup: Send + Sized + 'static;
    /// The future type that will resolve to a Lookup
    type LookupFuture: Future<Output = Result<Self::Lookup, LookupError>> + Send;

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName;

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vectory containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Get the NS, NameServer, record for the zone
    fn ns(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.lookup(
            self.origin(),
            RecordType::NS,
            is_secure,
            supported_algorithms,
            src,
        )
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    fn get_nsec_records(
        &self,
        name: &LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    fn soa(
        &self,
        src: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        // SOA should be origin|SOA
        self.lookup(
            self.origin(),
            RecordType::SOA,
            false,
            SupportedAlgorithms::new(),
            src,
        )
    }

    /// Returns the SOA record for the zone
    fn soa_secure(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.lookup(
            self.origin(),
            RecordType::SOA,
            is_secure,
            supported_algorithms,
            src,
        )
    }
}

impl<A, L> AuthorityObject for Arc<RwLock<A>>
where
    A: Authority<Lookup = L> + Send + Sync + 'static,
    A::LookupFuture: Send + 'static,
    L: LookupObject + Send + 'static,
{
    fn box_clone(&self) -> Box<dyn AuthorityObject> {
        Box::new(self.clone())
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> LowerName {
        Authority::origin(&*self.read()).clone()
    }

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> BoxedLookupFuture {
        let this = self.read();
        let lookup = Authority::lookup(&*this, name, rtype, is_secure, supported_algorithms, src);
        BoxedLookupFuture::from(lookup.map_ok(|l| Box::new(l) as Box<dyn LookupObject>))
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vectory containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        src: IpAddr,
    ) -> BoxedLookupFuture {
        let this = self.read();
        debug!("performing {} on {}", query, this.origin());
        let lookup = Authority::search(&*this, query, is_secure, supported_algorithms, src);
        BoxedLookupFuture::from(lookup.map_ok(|l| Box::new(l) as Box<dyn LookupObject>))
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    fn get_nsec_records(
        &self,
        name: &LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture {
        let lookup =
            Authority::get_nsec_records(&*self.read(), name, is_secure, supported_algorithms);
        BoxedLookupFuture::from(lookup.map_ok(|l| Box::new(l) as Box<dyn LookupObject>))
    }
}
