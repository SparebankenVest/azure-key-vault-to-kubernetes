require("dotenv").config();
const queries = require("./src/utils/algolia");
const config = require("./config");
const plugins = [
  'gatsby-plugin-catch-links',
  'gatsby-plugin-sitemap',
  'gatsby-plugin-sharp',
  {
    resolve: `gatsby-plugin-layout`,
    options: {
        component: require.resolve(`./src/templates/docs.js`)
    }
  },
  'gatsby-plugin-styled-components',
  {
    resolve: 'gatsby-plugin-mdx',
    options: {
      gatsbyRemarkPlugins: [
        {
          resolve: 'gatsby-remark-copy-linked-files'
        }
      ],
      extensions: [".mdx", ".md"]
    }
  },
  'gatsby-plugin-emotion',
  'gatsby-plugin-remove-trailing-slashes',
  'gatsby-plugin-react-helmet',
  {
    resolve: "gatsby-source-filesystem",
    options: {
      name: "docs",
      path: `${__dirname}/content`
    }
  },
  // {
  //   resolve: "gatsby-source-filesystem",
  //   options: {
  //     name: "tutorials",
  //     path: `${__dirname}/content/tutorials`
  //   }
  // },
  {
    resolve: '@stackbit/gatsby-plugin-menus',
    options: {
      // // static definition of menu items (optional)
      // menus: {
      //   main: // identifier of menu container
      //     [ // array of contained children menu items
      //       {
      //         identifier: 'myId', // identifier for this item (optional)
      //         title: 'Title for page',
      //         url: '/page-1/',
      //         weight: 1
      //       }
      //     ]
      // },
      // Gatsby node types from which we extract menus (optional, see "Advanced usage")
      sourceNodeType: 'MarkdownRemark', 
      // the relative node path where we can find the 'menus' container (optional)
      sourceDataPath: 'frontmatter',
      // the relative node path where we can find the page's URL (required)
      sourceUrlPath: 'fields.url',
      // // custom menu loading function (optional)
      // menuLoader: customLoaderFunction,
      // // the property to use for injecting to the page context (optional, see "Advanced usage")
      // pageContextProperty: 'menus',
    },
  },
  {
    resolve: 'gatsby-plugin-gtag',
    options: {
      // your google analytics tracking id
      trackingId: config.gatsby.gaTrackingId,
      // Puts tracking script in the head instead of the body
      head: true,
      // enable ip anonymization
      anonymize: false,
    },
  },
  {
    resolve: `gatsby-transformer-remark`,
    options: {
      plugins: [
        {
          resolve: 'gatsby-remark-table-of-contents',
          options: {
            exclude: "Table of Contents",
            tight: false,
            fromHeading: 1,
            toHeading: 6
          },
        },
        {
          resolve: "gatsby-remark-images",
          options: {
            maxWidth: 1035,
            sizeByPixelDensity: true,
            linkImagesToOriginal: true,
            showCaptions: true,
          }
        },
        {
          resolve: `gatsby-remark-prismjs`,
          options: {
            classPrefix: "language-",
            inlineCodeMarker: null,
            aliases: {},
            showLineNumbers: true,
            noInlineHighlight: false,
          },
        },
      ],
    },
  }, 
  'gatsby-plugin-robots-txt',
];
if (config.header.search && config.header.search.enabled && config.header.search.algoliaAppId && config.header.search.algoliaAdminKey) {
  plugins.push({
    resolve: `gatsby-plugin-algolia`,
    options: {
      appId: config.header.search.algoliaAppId, // algolia application id
      apiKey: config.header.search.algoliaAdminKey, // algolia admin key to index
      queries,
      chunkSize: 10000, // default: 1000
    }}
  )
}
module.exports = {
  pathPrefix: config.gatsby.pathPrefix,
  siteMetadata: {
    title: config.siteMetadata.title,
    description: config.siteMetadata.description,
    docsLocation: config.siteMetadata.docsLocation,
    ogImage: config.siteMetadata.ogImage,
    favicon: config.siteMetadata.favicon,
    logo: { link: config.header.logoLink ? config.header.logoLink : '/', image: config.header.logo }, // backwards compatible
    headerTitle: config.header.title,
    githubUrl: config.header.githubUrl,
    helpUrl: config.header.helpUrl,
    tweetText: config.header.tweetText,
    headerLinks: config.header.links,
    siteUrl: config.gatsby.siteUrl,
  },
  plugins: plugins
};
