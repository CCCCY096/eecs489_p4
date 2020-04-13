#!/bin/bash

# This script tags the state of the current branch and optionally pushes
# tags to the remote.  It also configures the local git repo to include tags
# during git push.

date=`date +%Y.%m.%d_%H.%M.%S`

# Make sure you're in a git repository with a file and initial commit
out=`git ls-tree --full-tree --name-only -r HEAD 2> /dev/null`
if [[ $? -ne 0 || "$out" = "" ]]; then
    echo "Error: no committed files in repository.  Please add files to your repository and commit."
    exit 1
fi

# Ignore signals, so users don't stop in an intermediate state
trap "" SIGINT SIGQUIT SIGTSTP

# Create temporary commit
git commit -am compile-${date} --allow-empty > /dev/null

if [[ $? -eq 0 ]]; then
    # create tag for the temporary commit (fail silently if tag already exists)
    git tag -a compile-${date} -m "" >& /dev/null

    # undo temporary commit
    git reset HEAD~ > /dev/null

    # Push tag (if requested on the command line).  Allow this to be killed
    # (without killing autotag.sh).
    if [[ "$1" = "push" ]]; then
	(trap - SIGINT SIGQUIT SIGTSTP; git push --tags)
    fi
fi

# Configure git to push tags (in addition to the current branch)
remote=`git remote | head -1`
config=`git config --get-all "remote.$remote.push"`
if [[ ! $config =~ refs/tags/\* ]]; then
    git config --add "remote.$remote.push" refs/tags/*
fi
if [[ ! $config =~ HEAD ]]; then
    git config --add "remote.$remote.push" HEAD
fi
