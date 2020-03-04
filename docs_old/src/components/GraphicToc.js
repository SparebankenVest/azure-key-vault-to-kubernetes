import React from 'react';
import {StaticQuery, graphql} from "gatsby";
import Link from "./link";
import './styles.css';

const GraphicToc = ({location}) => (
  <StaticQuery
  query={graphql`
    query {
      allMdx {
        edges {
          node {
            frontmatter {
              title
              metaDescription
              index
            }
            fields {
              slug
              title
            }
          }
        }
      }
    }
  `}
  
  render={({allMdx}) => {
    let filter = (edge) => {
      if(location) {
        return edge.node.fields.slug === location;
      }
      return edge.node.fields.slug.lastIndexOf('/') === 0 && edge.node.fields.slug !== "/";    
    };

    let topEdges = allMdx.edges
                    .filter(filter)
                    .sort((a, b) => {
                      return a.node.frontmatter.index - b.node.frontmatter.index;
                    } );

    return (
      <div style={{textAlign: "center"}}>
      {topEdges.map(edge => {
        return (
          <div className={'graphic-toc'}>
          <Link to={edge.node.fields.slug} className={'graphic-toc-link'}>
            <div className={'graphic-toc-wrapper'}>
              <div className={'graphic-toc-title'}>
                <span>{edge.node.fields.title}</span>
              </div>
              <div className={'graphic-toc-description'}>
                <span>{edge.node.frontmatter.metaDescription}</span>
              </div>
            </div>
          </Link>
        </div>
        );
      })}
      </div>
    );
  }}
/>
);

export default GraphicToc;