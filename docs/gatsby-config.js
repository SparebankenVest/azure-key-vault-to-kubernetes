const themeOptions = require('gatsby-theme-apollo-docs/theme-options');

module.exports = {
  pathPrefix: '/',
  plugins: [
    {
      resolve: 'gatsby-plugin-gtag',
      options: {
        // your google analytics tracking id
        trackingId: 'UA-136446489-2',
        // Puts tracking script in the head instead of the body
        head: true,
        // enable ip anonymization
        anonymize: false,
      },
    },
    {
      resolve: `gatsby-source-git`,
      options: {
        name: `default`,
        remote: `https://github.com/SparebankenVest/public-helm-charts.git`,
        // Optionally supply a branch. If none supplied, you'll get the default branch.
        // branch: `develop`,
        // Tailor which files get imported eg. import the docs folder from a codebase.
        patterns: [
          'stable/azure-key-vault-controller/README.md', 
          'stable/azure-key-vault-env-injector/README.md', 
          ]
      }
    },
    // {
    //   resolve: "gatsby-source-graphql",
    //   options: {
    //     // Arbitrary name for the remote schema Query type
    //     typeName: "GitHub",
    //     // Field under which the remote schema will be accessible. You'll use this in your Gatsby query
    //     fieldName: "github",
    //     // Url to query from
    //     url: "https://api.github.com/graphql",
    //     headers: {
    //       // Learn about environment variables: https://gatsby.dev/env-vars
    //       Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
    //     },
    //   },
    // },
    {
      resolve: 'gatsby-theme-apollo-docs',
      options: {
        ...themeOptions,
        root: __dirname,
        baseUrl: 'https://akv2k8s.io',
        baseDir: 'docs',
        logoLink: 'https://akv2k8s.io/',
        contentDir: 'source/content/',
        siteName: '',
        pageTitle: 'akv2k8s docs',
        subtitle: '',
        description: 'How to get Azure Key Vault objects into Kubernetes',
        githubRepo: 'sparebankenvest/azure-key-vault-to-kubernetes',
        segmentApiKey: null,
        algoliaApiKey: '3222f31991b019f454d81f025f0f26d3',
        algoliaIndexName: 'azure-key-vault-to-kubernetes',
        spectrumPath: '',
        spectrumHandle: '',
        twitterHandle: '',
        sidebarCategories: {
          null: ['index', 'why-akv2k8s', 'quick-start', 'how-it-works'],
          'Installation': [
            'installation/index',
            'installation/requirements',
            'installation/installing-with-helm',
            'installation/installing-without-helm',
            'installation/updating-with-helm',
          ],
          Tutorials: [
            'tutorials/index',
            'tutorials/prerequisites',
            'tutorials/sync/1-secret',
            'tutorials/sync/2-certificate',
            'tutorials/sync/3-signing-key',
            'tutorials/sync/4-multi-key-value-secret',
            'tutorials/env-injection/1-secret',
            'tutorials/env-injection/2-certificate',
            'tutorials/env-injection/3-signing-key',
            'tutorials/env-injection/5-pfx-certificate',
          ],
          Security: [
            'security/introduction',
            'security/authentication',
            'security/authorization',
            'security/enable-env-injection',
          ],
          'Availability': [
            'getting-started/scaling',
          ],
          Troubleshooting: [
            'troubleshooting/controller-log',
            'troubleshooting/env-injector-log-level',
            'troubleshooting/known-issues',
          ],
          Reference: [
            'reference/index',
            'reference/azure-key-vault-secret',
            'stable/azure-key-vault-controller/README',
            'stable/azure-key-vault-env-injector/README',
          ],
        },
        navConfig: {},
        // navConfig: {
        //   'Controller Basics': {
        //     url: 'https://www.apollographql.com/docs',
        //     description: 'Learn how the Controller syncs Azure Key Vault objects to Kubernetes as native Secrets.',
        //   },
        //   'Injector Basics': {
        //     url: 'https://www.apollographql.com/docs/apollo-server',
        //     description: 'Learn how the Injector injects Azure Key Vault objects as environment variabled directly into your application'
        //   },
        //   'When to use which': {
        //     url: 'https://www.apollographql.com/docs/apollo-server',
        //     description: 'Learn when to use the Controller and when to use the Injector'
        //   },
        // },
      },
    },
  ],
};
