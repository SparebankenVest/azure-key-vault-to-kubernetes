# Documentation for Azure Key Vault to Kubernetes (akv2k8s)

We're using Gatsby + MDX (Markdown + JSX) to generate
static docs for https://akv2k8s.io  

## Development

Get started by running the following commands:

```
npm install
npm run start
```

Visit `http://localhost:8000/` to view the docs.

## Changing / Adding Documentation

Documentation files are in markdown and located in the `content` folder.

For sub nesting in left sidebar, create a folder with the same name as the top level `.md` filename and the sub navigation is auto-generated. The sub navigation is alphabetically ordered.

Every page must use meta tags for title and description.

```markdown
---
title: "Title of the page"
metaTitle: "Meta Title Tag for this page"
metaDescription: "Meta Description Tag for this page"
---
```

## Deploy

Deployment is automated with GitHub Actions and triggers on
every push to the `/docs` folder in the `master` branch.