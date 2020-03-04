const themeOptions = require('gatsby-theme-apollo-docs/theme-options');

module.exports = {
  pathPrefix: '/',
  plugins: [
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
        algoliaApiKey: '',
        algoliaIndexName: '',
        spectrumPath: '',
        spectrumHandle: '',
        twitterHandle: '',
        defaultVersion: '1.0.0',
        versions: {
          '0.1.15': 'doc-version-0.1.15'
        },
        sidebarCategories: {
          null: ['index', 'why-akv2k8s', 'quick-start', 'how-it-works', 'examples'],
          'Installation': [
            'installation/introduction',
            'installation/requirements',
            'installation/installing-with-helm',
            'installation/installing-without-helm',
          ],
          Tutorials: [
            'tutorials/introduction',
            'tutorials/prerequisites',
            'tutorials/sync/1-secret',
            'tutorials/sync/2-certificate',
            'tutorials/sync/3-signing-key',
            'tutorials/sync/4-multi-value-secret',
            'tutorials/env-injection/1-secret',
            'tutorials/env-injection/2-certificate',
            'tutorials/env-injection/3-signing-key',
            'tutorials/env-injection/4-multi-value-secret',
            'tutorials/env-injection/5-env-injector-pfx-certificate',
          ],
          Security: [
            'security/introduction',
            'security/authentication',
            'security/authorization',
          ],
          'Scaling and Availability': [
            'getting-started/scaling',
          ],
          Troubleshooting: [
            'troubleshooting/controller-log',
            'troubleshooting/env-injector-log-level',
            'troubleshooting/known-issues',
          ],
          Reference: [
            'reference/reference',
            'reference/vault-object-types',
            'reference/kubernetes-secret-types',
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
