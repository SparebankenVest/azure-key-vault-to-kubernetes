# Documentation for Azure Key Vault to Kubernetes (akv2k8s)

We're using Gatsby + MDX (Markdown + JSX) to generate
static docs for https://akv2k8s.io  

## Development

Get started by running the following commands:

```
npm install
npm run dev
```

Visit `http://localhost:8000/` to view the docs.

## Changing / Adding Documentation

Documentation files are in markdown and located in the `content` folder.

For sub nesting in left sidebar, create a folder with the same name as the top level `.md` filename and the sub navigation is auto-generated. 

Every page must use meta tags for title, description and index.

```markdown
---
title: "Title of the page"
metaTitle: "Meta Title Tag for this page"
metaDescription: "Meta Description Tag for this page"
index: 4
---
```

The sub navigation is ordered on each level using the `index` meta tag.

## Deploy

Deployment is automated with GitHub Actions and triggers on
every push to the `/docs` folder in the `master` branch.