.SILENT:
MAKEFLAGS += --no-print-directory
.SHELLFLAGS = -euc
SHELL = /bin/bash

#######################
## Templates
#######################
## Mergify template
define MERGIFY_TMPL

  - name: backport patches to $(BRANCH) branch
    conditions:
      - merged
      - base=main
      - label=$(BACKPORT_LABEL)
    actions:
      backport:
        assignees:
          - "{{ author }}"
        branches:
          - "$(BRANCH)"
        labels:
          - "backport"
        title: "[{{ destination_branch }}] {{ title }} (backport #{{ number }})"
endef

# Add mergify entry for the new backport label
.PHONY: mergify
export MERGIFY_TMPL
mergify: BACKPORT_LABEL=$${BACKPORT_LABEL} BRANCH=$${BRANCH} PUSH_BRANCH=$${PUSH_BRANCH}
mergify:
	@echo ">> mergify"
	echo "$$MERGIFY_TMPL" >> ../.mergify.yml
	git add ../.mergify.yml
	git status
	if [ ! -z "$$(git status --porcelain)" ]; then \
		git commit -m "mergify: add $(BACKPORT_LABEL) rule"; \
		git push origin $(PUSH_BRANCH) ; \
	fi

# Create GitHub backport label
.PHONY: backport-label
backport-label: BACKPORT_LABEL=$${BACKPORT_LABEL}
backport-label:
	@echo ">> backport-label"
	gh label create $(BACKPORT_LABEL) --description "Automated backport with mergify" --color 0052cc --force
