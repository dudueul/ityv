---------------------------- MODULE LedgerWitness ----------------------------
(***************************************************************************)
(* ityv ledger / witness checkpoint protocol, safety model (ADR-0012,      *)
(* PROTOCOL.md section 5.4).                                               *)
(*                                                                         *)
(* The ledger operator (the election commission) is untrusted: it may      *)
(* propose any checkpoint body at any sequence number, including bodies    *)
(* whose log prefixes fork.  Honest witnesses sign a body only if it is    *)
(* the next sequence number after the last body they signed and its log   *)
(* prefix extends that body's prefix (the consistency proof).  Honest      *)
(* witnesses never sign two bodies at the same sequence number.            *)
(* Byzantine witnesses sign everything, which is the worst case for        *)
(* quorum counting.  A body is published when it has Quorum signatures.    *)
(*                                                                         *)
(* Safety properties checked:                                              *)
(*   Agreement: no two distinct published bodies share a sequence number.  *)
(*   Linear:    any two published bodies have prefix-ordered logs, so the  *)
(*              published history never forks.                             *)
(* Both follow from 2*Quorum - |Witnesses| > |Byzantine|: two quorums     *)
(* intersect in more witnesses than can be Byzantine, so an honest witness *)
(* signed both, and honest witnesses only extend what they signed before.  *)
(*                                                                         *)
(* Not modelled: liveness, signature forgery, the content of events, the   *)
(* box-close and dispute roots inside a body, and external pins.           *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Witnesses,   \* set of witness identities
          Quorum,      \* signatures required to publish a checkpoint
          Byzantine,   \* witnesses that may sign anything
          Events,      \* abstract event alphabet of the log
          MaxLen,      \* bound on log length (model checking only)
          MaxSeq       \* bound on checkpoint sequence numbers

ASSUME Byzantine \subseteq Witnesses
ASSUME Quorum \in Nat /\ Quorum <= Cardinality(Witnesses)
ASSUME 2 * Quorum - Cardinality(Witnesses) > Cardinality(Byzantine)

Honest == Witnesses \ Byzantine

(* All log prefixes up to MaxLen over the abstract alphabet. *)
Prefixes == UNION { [1..n -> Events] : n \in 0..MaxLen }

(* A checkpoint body: its sequence number and the log prefix it commits to.
   tree_size is Len(prefix); root_hash is abstracted by the prefix itself. *)
Bodies == [seq : 1..MaxSeq, prefix : Prefixes]

IsPrefix(p, q) == Len(p) <= Len(q) /\ SubSeq(q, 1, Len(p)) = p

None == [seq |-> 0, prefix |-> << >>]

VARIABLES
  lastSigned,   \* honest witness -> last body it signed, or None
  sigs          \* set of <<witness, body>> signatures

vars == <<lastSigned, sigs>>

(* Byzantine witnesses have (potentially) signed everything from the start. *)
ByzantineSigs == { <<w, b>> : w \in Byzantine, b \in Bodies }

Signers(b) == { w \in Witnesses : <<w, b>> \in sigs }

Published == { b \in Bodies : Cardinality(Signers(b)) >= Quorum }

TypeOK ==
  /\ lastSigned \in [Honest -> Bodies \cup {None}]
  /\ sigs \subseteq (Witnesses \X Bodies)

Init ==
  /\ lastSigned = [w \in Honest |-> None]
  /\ sigs = ByzantineSigs

(* An honest witness signs body b only as the next step of its own chain. *)
HonestSign(w, b) ==
  /\ w \in Honest
  /\ b \in Bodies
  /\ b.seq = lastSigned[w].seq + 1
  /\ IsPrefix(lastSigned[w].prefix, b.prefix)
  /\ lastSigned' = [lastSigned EXCEPT ![w] = b]
  /\ sigs' = sigs \cup { <<w, b>> }

Next == \E w \in Honest, b \in Bodies : HonestSign(w, b)

Spec == Init /\ [][Next]_vars

(* ---- Safety properties ------------------------------------------------ *)

Agreement ==
  \A b1, b2 \in Published : b1.seq = b2.seq => b1 = b2

Linear ==
  \A b1, b2 \in Published : b1.seq < b2.seq => IsPrefix(b1.prefix, b2.prefix)

(* Honest witnesses never sign two different bodies at one sequence number. *)
OneHeadPerSeq ==
  \A w \in Honest, b1, b2 \in Bodies :
    (<<w, b1>> \in sigs /\ <<w, b2>> \in sigs /\ b1.seq = b2.seq) => b1 = b2

=============================================================================
