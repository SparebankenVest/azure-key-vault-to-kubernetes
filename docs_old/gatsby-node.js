const componentWithMDXScope = require("gatsby-plugin-mdx/component-with-mdx-scope");
const path = require("path");
const startCase = require("lodash.startcase");
const {createFilePath} = require(`gatsby-source-filesystem`);

exports.createPages = ({ graphql, actions }) => {
  const { createPage } = actions;
  return new Promise((resolve, reject) => {
    resolve(
      graphql(
        `
          {
            allMdx {
              edges {
                node {
                  fields {
                    id
                    slug
                  }
                  tableOfContents
                }
              }
            }
          }
        `
      ).then(result => {
        if (result.errors) {
          console.log(result.errors); // eslint-disable-line no-console
          reject(result.errors);
        }

        // Create regular pages.
        // result.data.allMdx.edges.filter(e => e.node.fields.slug.startsWith("/docs/")).forEach(({ node }) => {
        //   createPage({
        //     path: node.fields.slug ? node.fields.slug : "/",
        //     component: path.resolve("./src/templates/page.jsx"),
        //     context: {
        //       id: node.childMdx.fields.id
        //     }
        //   });
        // });
        
        // Create docs pages.
        result.data.allMdx.edges.filter(e => e.node.fields.slug.startsWith("/docs/")).forEach(({ node }) => {
          createPage({
            path: node.fields.slug ? node.fields.slug : "/docs/",
            component: path.resolve("./src/templates/docs.js"),
            context: {
              id: node.fields.id
            }
          });
        });

        // // Create tutorials pages.
        // result.data.allFile.edges.filter(e => e.node.sourceInstanceName === 'tutorials' && e.node.childMdx).forEach(({ node }) => {
        //   createPage({
        //     path: node.childMdx.fields.slug ? `/tutorials${node.childMdx.fields.slug}` : "/tutorials/",
        //     component: path.resolve("./src/templates/tutorials.js"),
        //     context: {
        //       id: node.childMdx.fields.id
        //     }
        //   });
        // });
        
      })
    );
  });
};

exports.onCreateWebpackConfig = ({ actions }) => {
  actions.setWebpackConfig({
    resolve: {
      modules: [path.resolve(__dirname, "src"), "node_modules"],
      alias: { $components: path.resolve(__dirname, "src/components") }
    }
  });
};

exports.onCreateBabelConfig = ({ actions }) => {
  actions.setBabelPlugin({
    name: "@babel/plugin-proposal-export-default-from"
  });
};

exports.onCreateNode = ({ node, getNode, actions }) => {
  const { createNodeField } = actions;

  if (node.internal.type === `Mdx`) {
    let value = createFilePath({ node, getNode, basePath: 'src/content' });

    createNodeField({
      name: `slug`,
      node,
      value: `${value}`
    });

    createNodeField({
      name: "id",
      node,
      value: node.id
    });

    createNodeField({
      name: "title",
      node,
      value: node.frontmatter.title || startCase(parent.name)
    });
  }
};
