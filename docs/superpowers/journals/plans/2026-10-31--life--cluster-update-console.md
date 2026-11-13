<!-- fr:journal-schema=4 -->
# Journal: 2026-10-31--life--cluster-update-console

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P1.T1 created=2026-10-31T19:48:14+00:00 phase=1 -->
### no-refactor-because-P1.T1 · discovery · no-refactor-because P1.T1: skeleton task: config + healthz + workflows, no duplication to clean (phase 1)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P1.T3 created=2026-10-31T19:48:31+00:00 phase=1 -->
### no-refactor-because-P1.T3 · discovery · no-refactor-because P1.T3: version and frankrepo are separate small packages; the policy matcher was written once (phase 1)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P2.T1 created=2026-10-31T19:48:32+00:00 phase=2 -->
### no-refactor-because-P2.T1 · discovery · no-refactor-because P2.T1: forge HTTP plumbing was factored into one client.do from the start (phase 2)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P2.T2 created=2026-10-31T19:48:34+00:00 phase=2 -->
### no-refactor-because-P2.T2 · discovery · no-refactor-because P2.T2: renovate parsing is three regexes and one shared setter; nothing duplicated (phase 2)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P2.T3 created=2026-10-31T19:48:36+00:00 phase=2 -->
### no-refactor-because-P2.T3 · discovery · no-refactor-because P2.T3: engine cleanup done in the follow-up in-batch fix; merge/record paths already shared (phase 2)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P3.T1 created=2026-10-31T19:57:00+00:00 phase=3 -->
### no-refactor-because-P3.T1 · discovery · no-refactor-because P3.T1: store transition logic is one function used by Transition, Record and Reconcile (phase 3)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P3.T2 created=2026-10-31T19:57:03+00:00 phase=3 -->
### no-refactor-because-P3.T2 · discovery · no-refactor-because P3.T2: verify is pure functions over inputs; no duplication between workload and OS paths beyond the smoke summary helper (phase 3)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P3.T3 created=2026-10-31T19:57:06+00:00 phase=3 -->
### no-refactor-because-P3.T3 · discovery · no-refactor-because P3.T3: alarm and telegram are separate small packages; formatting shares one escape helper (phase 3)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P4.T1 created=2026-10-31T20:09:54+00:00 phase=4 -->
### no-refactor-because-P4.T1 · discovery · no-refactor-because P4.T1: id and lock code are two small pure helpers with one storage path (UpdateBlob) (phase 4)

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P4.T2 created=2026-10-31T20:10:01+00:00 phase=4 -->
### no-refactor-because-P4.T2 · discovery · no-refactor-because P4.T2: the launch path's cleanup was folded into the shared cleanup() in P4.T3.S3 (phase 4)

<!-- fr:journal kind=discovery scope=plan id=deviation-p4-no-rolebinding created=2026-10-31T20:10:09+00:00 phase=4 -->
### deviation-p4-no-rolebinding · discovery · deviation P4.T2.S1: the console creates NO per-upgrade RoleBinding (phase 4)

Security review (coordinator, 2026-10-31) restricted the kube write allowlist to create/delete of pods, secrets and rolebindings in the session namespace only, nothing in other namespaces. A RoleBinding granting Longhorn-snapshot or Rollout-status rights must live in the APP namespace, so the console cannot create it. frank must pre-bind those Roles to the per-type ServiceAccounts upgrade-session-stateful / upgrade-session-rollouts (scoped per app namespace), or the session must obtain the grant another way. Frank's plan P5.T1.S1 ('bound per app at launch by the console via a RoleBinding template') and P4.T1.S1's RBAC exception need to change accordingly.

<!-- fr:journal kind=discovery scope=plan id=no-refactor-because-P5.T1 created=2026-10-31T20:34:18+00:00 phase=5 -->
### no-refactor-because-P5.T1 · discovery · no-refactor-because P5.T1: templates share one item partial and one button helper (phase 5)
