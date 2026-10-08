//! Read-only database-free inventory query and graph traversal APIs.
use crate::{Asset, AssetId, AssetKind, Confidence, Evidence, InventoryError, InventorySnapshot, Observation, Relationship, RelationshipKind};
use std::collections::{BTreeSet,VecDeque};

/// Immutable, filtered view of canonical inventory assets.
pub struct InventoryQuery<'a> {
    assets: Vec<&'a Asset>,
}
impl<'a> InventoryQuery<'a> {
    /// Filter via a typed predicate without I/O.
    pub fn filter(mut self, predicate:impl Fn(&Asset)->bool)->Self{
        self.assets.retain(|a|predicate(a));
        self
    }
    /// Filter by canonical asset kind name.
    pub fn kind(self,kind:&str)->Self{
        self.filter(|a|a.kind.name()==kind)
    }
    /// Filter by normalized algorithm family or exact profile.
    pub fn algorithm(self,needle:&str)->Self{
        self.filter(|a|matches!(&a.kind,AssetKind::AlgorithmUse{family,profile,..}
            if family.eq_ignore_ascii_case(needle) || profile.as_deref()==Some(needle)))
    }
    /// Filter by protocol family and optional observation state.
    pub fn protocol(self,family:&str)->Self{
        self.filter(|a|matches!(&a.kind,AssetKind::Protocol{family:f,..} if f.eq_ignore_ascii_case(family)))
    }
    /// Filter by package ecosystem and name.
    pub fn package(self,ecosystem:&str,name:&str)->Self{
        self.filter(|a|matches!(&a.kind,AssetKind::Library{ecosystem:e,name:n,..}
            if e.eq_ignore_ascii_case(ecosystem)&&n.eq_ignore_ascii_case(name)))
    }
    /// Filter by a provider identifier.
    pub fn provider(self,provider:&str)->Self{
        self.filter(|a|match &a.kind{
            AssetKind::Key{provider:p,..}=>p.as_deref()==Some(provider),
            AssetKind::KeyStore{provider:p,..}=>p==provider,
            AssetKind::Provider{name,..}=>name==provider,
            _=>false
        })
    }
    /// Filter by certificate fingerprint.
    pub fn certificate(self,fingerprint:&str)->Self{
        self.filter(|a|matches!(&a.kind,AssetKind::Certificate{fingerprint_sha256,..}
            if fingerprint_sha256.eq_ignore_ascii_case(fingerprint)))
    }
    /// Filter by endpoint host.
    pub fn endpoint(self,host:&str)->Self{
        self.filter(|a|matches!(&a.kind,AssetKind::Endpoint{host:h,..} if h.eq_ignore_ascii_case(host)))
    }
    /// Collect deterministic asset IDs, with a maximum result cap.
    pub fn ids(&self,max:usize)->Result<Vec<AssetId>,InventoryError>{
        if self.assets.len()>max {return Err(InventoryError::LimitExceeded("query results"));}
        Ok(self.assets.iter().map(|a|a.id.clone()).collect())
    }
    /// Iterate the matching canonical assets.
    pub fn iter(&self)->impl Iterator<Item=&'a Asset>+'_{
        self.assets.iter().copied()
    }
}
impl AssetKind {
    /// Stable name used by the query API.
    pub fn name(&self)->&'static str {
        match self{
            Self::AlgorithmUse{..}=>"algorithm-use",
            Self::Key{..}=>"key",
            Self::Certificate{..}=>"certificate",
            Self::Protocol{..}=>"protocol",
            Self::Endpoint{..}=>"endpoint",
            Self::Library{..}=>"library",
            Self::Runtime{..}=>"runtime",
            Self::KeyStore{..}=>"keystore",
            Self::SourceUse{..}=>"source-use",
            Self::TrustAnchor{..}=>"trust-anchor",
            Self::Extension{..}=>"extension",
            Self::Provider{..}=>"provider",
            Self::CryptoImplementation{..}=>"implementation",
            Self::Authority{..}=>"authority",
        }
    }
}
impl InventorySnapshot {
    /// Begin querying canonical assets in stable identity order.
    pub fn query(&self)->InventoryQuery<'_>{InventoryQuery{assets:self.assets.values().collect()}}
    /// Observations from a specified collector with at least the requested confidence.
    pub fn observations_by_collector<'a>(&'a self,collector:&str,min:Confidence)->Vec<&'a Observation>{
        self.observations.values().filter(|o|self.evidence.get(&o.evidence)
            .is_some_and(|e|e.collector.as_str()==collector && e.confidence>=min)).collect()
    }
    /// Observations having a source locator substring and specified minimum confidence.
    pub fn observations_by_source<'a>(&'a self,needle:&str,min:Confidence)->Vec<&'a Observation>{
        self.observations.values().filter(|o|self.evidence.get(&o.evidence)
            .is_some_and(|e|e.source.contains(needle)&&e.confidence>=min)).collect()
    }
    /// Evidence backing a specific observation.
    pub fn evidence_for(&self,observation:&Observation)->Option<&Evidence>{
        self.evidence.get(&observation.evidence)
    }
    /// Relationships of a specified kind, incident to an asset.
    pub fn relations_of<'a>(&'a self,asset:&AssetId,kind:Option<RelationshipKind>)->Vec<&'a Relationship>{
        self.relationships.values().filter(|r|(&r.from==asset||&r.to==asset)
            && kind.as_ref().is_none_or(|k|k==&r.kind)).collect()
    }
    /// Traverse outgoing relationships with depth and result limits.
    pub fn traverse(&self,start:&AssetId,kind:Option<RelationshipKind>,max_depth:usize,max_results:usize)
        ->Result<BTreeSet<AssetId>,InventoryError>{
        if !self.assets.contains_key(start){return Err(InventoryError::MissingAsset(start.to_string()));}
        let mut visited=BTreeSet::new();
        let mut todo=VecDeque::from([(start.clone(),0usize)]);
        visited.insert(start.clone());
        while let Some((current,depth))=todo.pop_front(){
            if depth>=max_depth{continue;}
            for r in self.relationships.values().filter(|r|r.from==current
                && kind.as_ref().is_none_or(|k|k==&r.kind)){
                if visited.insert(r.to.clone()){
                    if visited.len()>max_results{return Err(InventoryError::LimitExceeded("graph traversal"));}
                    todo.push_back((r.to.clone(),depth+1));
                }
            }
        }
        Ok(visited)
    }
}
