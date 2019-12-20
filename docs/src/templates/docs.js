import React, { Component } from "react";
import Helmet from "react-helmet";
import { graphql } from "gatsby";
import MDXRenderer from "gatsby-plugin-mdx/mdx-renderer";
import styled, { injectGlobal } from "react-emotion";
import { Layout, Link } from "$components";
import NextPrevious from '../components/NextPrevious';
import '../components/styles.css';
import 'prismjs/themes/prism-coy.css';
import 'prismjs/plugins/command-line/prism-command-line.css';
import Feedback from '../components/Feedback';

import config from '../../config';

const forcedNavOrder = config.sidebar.forcedNavOrder;

// "Playfair Display",
// -apple-system,
//   BlinkMacSystemFont,
//   "Segoe UI",
//   "Roboto",
//   "Roboto Light",
//   "Oxygen",
//   "Ubuntu",
//   "Cantarell",
//   "Fira Sans",
//   "Droid Sans",
//   "Helvetica Neue",
//   sans-serif,
//   "Apple Color Emoji",
//   "Segoe UI Emoji",
//   "Segoe UI Symbol";

injectGlobal`
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  html, body {
    font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;
    font-size: 18px;
    letter-spacing: .015em;
  }

  a {
    transition: color 0.15s;
    color: #168993;
  }
`;

const Edit = styled('div')`
  padding: 1rem 1.5rem;
  text-align: right;

  a {
    font-weight: 500;
    line-height: 1em;
    text-decoration: none;
    color: #555;
    border: 1px solid rgb(211, 220, 228);
    cursor: pointer;
    border-radius: 3px;
    transition: all 0.2s ease-out 0s;
    text-decoration: none;
    color: rgb(36, 42, 49);
    background-color: rgb(255, 255, 255);
    box-shadow: rgba(116, 129, 141, 0.1) 0px 1px 1px 0px;
    height: 30px;
    padding: 5px 16px;
    &:hover {
      background-color: rgb(245, 247, 249);
    }
  }
`;

export default class MDXRuntimeTest extends Component {
  render() {
    const { data } = this.props;
    const {
      allMdx,
      mdx,
      site: {
        siteMetadata: { docsLocation, title }
      }
    } = data;
    const gitHub = require('../components/images/github.svg');

    const navItems = allMdx.edges
      .sort((a, b) => {
        if(a.node.frontmatter.index && b.node.frontmatter.index) {
          return a.node.frontmatter.index - b.node.frontmatter.index;
        }
        let a_slug = a.node.fields.slug;
        let b_slug = b.node.fields.slug;

        if (a_slug > b_slug) {
          return 1;
        } else if (a_slug < b_slug) {
          return -1;
        } else if (a_slug === b_slug) {
          return 0;
        }
      })
      .map(({ node }) => node.fields.slug)
      .filter(slug => slug !== "/")
      .reduce(
        (acc, cur) => {
          if (forcedNavOrder.find(url => url === cur)) {
            return { ...acc, [cur]: [cur] };
          }

          const prefix = cur.split("/")[1];

          if (prefix && forcedNavOrder.find(url => url === `/${prefix}`)) {
            return { ...acc, [`/${prefix}`]: [...acc[`/${prefix}`], cur] };
          } else {
            return { ...acc, items: [...acc.items, cur] };
          }
        },
        { items: [] }
      );

    const nav = forcedNavOrder
      .reduce((acc, cur) => {
        return acc.concat(navItems[cur]);
      }, [])
      .concat(navItems.items)
      .map(slug => {
        if(slug) {
          const { node } = allMdx.edges.find(
            ({ node }) => node.fields.slug === slug
          );

          return { title: node.fields.title, url: node.fields.slug };
        }
      });

    // meta tags
    const metaTitle = mdx.frontmatter.metaTitle;
    const metaDescription = mdx.frontmatter.metaDescription;
    let canonicalUrl = config.gatsby.siteUrl;
    canonicalUrl = config.gatsby.pathPrefix !== '/' ? canonicalUrl + config.gatsby.pathPrefix : canonicalUrl;
    canonicalUrl = canonicalUrl + mdx.fields.slug;

    let disqusConfig = {
      url: canonicalUrl,
      identifier: mdx.fields.id,
      title: mdx.fields.title,
    }

    return (
      <Layout {...this.props}>
        <Helmet>
          {metaTitle ? <title>{metaTitle}</title> : null }
          {metaTitle ? <meta name="title" content={metaTitle} /> : null}
          {metaDescription ? <meta name="description" content={metaDescription} /> : null}
          {metaTitle ? <meta property="og:title" content={metaTitle} /> : null}
          {metaDescription ? <meta property="og:description" content={metaDescription} /> : null}
          {metaTitle ? <meta property="twitter:title" content={metaTitle} /> : null}
          {metaDescription ? <meta property="twitter:description" content={metaDescription} /> : null}
          <link rel="canonical" href={canonicalUrl} />
        </Helmet>
        <div className={'titleWrapper'}>
          <h1 className={'title'}>
            {mdx.fields.title}
          </h1>
          <Edit className={'mobileView'}>
            <Link className={'gitBtn'} to={`${docsLocation}/${mdx.parent.relativePath}`}>
              <img src={gitHub} alt={'Github logo'} /> Edit on GitHub
            </Link>
          </Edit>
        </div>
        <div className={'mainWrapper'}>
          <MDXRenderer>{mdx.body}</MDXRenderer>
        </div>
        <div className={'addPaddTopBottom'}>
          <NextPrevious mdx={mdx} nav={nav} />
        </div>
        <Feedback />
      </Layout>
    );
  }
}

export const pageQuery = graphql`
  query($id: String!) {
    site {
      siteMetadata {
        title
        docsLocation
      }
    }
    mdx(fields: { id: { eq: $id } }) {
      fields {
        id
        title
        slug
      }
      body
      tableOfContents
      parent {
        ... on File {
          relativePath
        }
      }
      frontmatter {
        metaTitle
        metaDescription
        index
      }
    }
    allMdx {
      edges {
        node {
          fields {
            slug
            title
          }
          frontmatter {
            index
          }
        }
      }
    }
  }
`;
