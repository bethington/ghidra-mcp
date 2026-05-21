Subject: Detach fork (child forks present) — bethington/ghidra-mcp from LaurieWired/GhidraMCP

Hi GitHub Support,

I'd like to request that my repository be detached from its parent
fork and converted to a standalone repository. I attempted the
self-service path under repository Settings → "Leave fork network"
and received:

  "Can't leave the fork network because this fork has child forks."

My repository currently has 149 child forks, so I cannot complete
this through the UI and am asking your team to perform the
detachment.

Repository details:
- Fork to detach:  https://github.com/bethington/ghidra-mcp
- Parent upstream: https://github.com/LaurieWired/GhidraMCP
- I am the owner of the fork (bethington).
- Child fork count at time of request: 149 (the vast majority are
  stale clones with zero stars and no original commits).

Reason:
The project has diverged substantially from the upstream since the
fork was created in August 2025 — different architecture (service
layer, annotation-driven endpoint scanner, separate headless server),
a different scope (244 MCP tools vs. the upstream's roughly 20),
eleven independent minor releases (currently v5.11.0), its own issue
and PR history, its own sponsors program, and no shared roadmap with
the upstream. Continuing to be classified as a fork in the GitHub UI no
longer reflects the relationship between the two projects and is
causing friction for discoverability, sponsor messaging, and
contributor onboarding.

Upstream attribution will continue to be preserved in the repository
itself (LICENSE / NOTICE / README), independent of the GitHub fork
link, as required by the Apache 2.0 license.

Handling of child forks:
I have no preference about how the 149 child forks are re-parented
after the detachment — whether they are re-parented to the original
upstream (LaurieWired/GhidraMCP), left as root repositories with no
parent, or handled in some other way that is standard for your team.
I am not asking for any change to be made to those repositories
beyond what is required for my own to leave the network. Please
proceed with whatever your standard process is for this situation
and let me know in your reply what was done so I can document it.

I understand that:
- Detaching is a one-way operation and cannot be undone.
- The "forked from" link in the GitHub UI will be removed from
  bethington/ghidra-mcp.
- Issues, pull requests, stars, releases, Discussions, and watchers
  should all remain attached to bethington/ghidra-mcp after the
  detachment — please confirm in your reply if there are any
  exceptions.

Please proceed with the detachment when convenient. Happy to provide
any additional verification you need.

Thanks,
Ben Ethington
benaminde@gmail.com
GitHub: @bethington
