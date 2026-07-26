-------------------------- MODULE CapabilitySecurity --------------------------
EXTENDS Naturals, FiniteSets, Sequences

\* A small executable model of the reference-monitor invariants.  Concrete
\* resource selectors and labels are abstracted into finite sets so TLC can
\* exhaustively explore grant, delegation, revocation, update, and transaction
\* interleavings.

CONSTANTS Artifacts, Rights, Resources, Principals, NoArtifact

ASSUME /\ Artifacts # {}
       /\ Rights # {}
       /\ Resources # {}
       /\ Principals # {}
       /\ NoArtifact \notin Artifacts

VARIABLES currentArtifact, grants, revoked, authority, effects, inverses,
          denied, decisions

vars == <<currentArtifact, grants, revoked, authority, effects, inverses, denied,
          decisions>>

Init ==
    /\ currentArtifact \in Artifacts
    /\ grants = {}
    /\ revoked = {}
    /\ authority = {}
    /\ effects = {}
    /\ inverses = {}
    /\ denied = {}
    /\ decisions = <<>>

ActiveGrant(g) ==
    /\ g \in grants
    /\ g \notin revoked
    /\ g[1] = currentArtifact

Grant(a, p, r, x) ==
    /\ a = currentArtifact
    /\ grants' = grants \cup {<<a, p, r, x>>}
    /\ UNCHANGED <<currentArtifact, revoked, authority, effects, inverses,
                   denied, decisions>>

Acquire(g) ==
    /\ ActiveGrant(g)
    /\ authority' = authority \cup {
          [artifact |-> g[1],
           principal |-> g[2],
           rights |-> {g[3]},
           parentRights |-> {g[3]},
           resource |-> g[4],
           sourceGrant |-> g]}
    /\ UNCHANGED <<currentArtifact, grants, revoked, effects, inverses,
                   denied, decisions>>

Revoke(g) ==
    /\ g \in grants
    /\ revoked' = revoked \cup {g}
    /\ authority' = {
          a \in authority : a.sourceGrant # g}
    /\ UNCHANGED <<currentArtifact, grants, effects, inverses, denied,
                   decisions>>

Delegate(parent, childArtifact, childRights) ==
    /\ parent \in authority
    /\ childArtifact = currentArtifact
    /\ childRights \subseteq parent.rights
    /\ authority' = authority \cup {
          [artifact |-> childArtifact,
           principal |-> parent.principal,
           rights |-> childRights,
           parentRights |-> parent.rights,
           resource |-> parent.resource,
           sourceGrant |-> parent.sourceGrant]}
    /\ UNCHANGED <<currentArtifact, grants, revoked, effects, inverses,
                   denied, decisions>>

UpdateArtifact(next) ==
    /\ next \in Artifacts
    /\ next # currentArtifact
    /\ currentArtifact' = next
    /\ authority' = {}
    /\ UNCHANGED <<grants, revoked, effects, inverses, denied, decisions>>

Prepare(tx, effect) ==
    /\ \A pair \in inverses : pair[1] # tx
    /\ inverses' = inverses \cup {<<tx, effect>>}
    /\ UNCHANGED <<currentArtifact, grants, revoked, authority, effects,
                   denied, decisions>>

Commit(tx, effect) ==
    /\ <<tx, effect>> \in inverses
    /\ effect \notin denied
    /\ effects' = effects \cup {effect}
    /\ decisions' = Append(decisions, <<"allow", effect>>)
    /\ UNCHANGED <<currentArtifact, grants, revoked, authority, inverses,
                   denied>>

Deny(effect) ==
    /\ effect \notin effects
    /\ denied' = denied \cup {effect}
    /\ decisions' = Append(decisions, <<"deny", effect>>)
    /\ UNCHANGED <<currentArtifact, grants, revoked, authority, effects,
                   inverses>>

Next ==
    \/ \E a \in Artifacts, p \in Principals, r \in Rights, x \in Resources:
           Grant(a, p, r, x)
    \/ \E g \in grants: Revoke(g)
    \/ \E g \in grants: Acquire(g)
    \/ \E parent \in authority,
          childArtifact \in Artifacts,
          childRights \in SUBSET Rights:
           Delegate(parent, childArtifact, childRights)
    \/ \E a \in Artifacts: UpdateArtifact(a)
    \/ \E tx \in Nat, effect \in Resources: Prepare(tx, effect)
    \/ \E tx \in Nat, effect \in Resources: Commit(tx, effect)
    \/ \E effect \in Resources: Deny(effect)

ArtifactBound ==
    \A g \in grants : g[1] \in Artifacts

RevokedGrantInactive ==
    revoked \subseteq grants

AuthorityAttenuates ==
    \A a \in authority : a.rights \subseteq a.parentRights

AuthorityUsesActiveArtifact ==
    \A a \in authority :
        /\ a.artifact = currentArtifact
        /\ ActiveGrant(a.sourceGrant)

ReversibleEffectHasInverse ==
    \A effect \in effects : \E tx \in Nat : <<tx, effect>> \in inverses

DeniedHasNoTransition == denied \cap effects = {}

Spec == Init /\ [][Next]_vars

=============================================================================
