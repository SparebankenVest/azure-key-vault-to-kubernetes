import React from 'react';
import {ReactComponent as Akv2k8s} from '../../akv2k8s_small.svg';
import {graphql, useStaticQuery} from 'gatsby';
import styled from '@emotion/styled';

const Wrapper = styled.div({
  display: 'flex',
  alignItems: 'center'
});

const Title = styled.span({
  fontSize: 24,
  marginLeft: 16
});

export default function Logo() {
  const data = useStaticQuery(
    graphql`
      {
        site {
          siteMetadata {
            title
          }
        }
      }
    `
  );

  return (
    <Wrapper>
      <Akv2k8s width={50} height={50} />
      <Title style={{color: "#326CE5"}}>
        {data.site.siteMetadata.title}
      </Title>
    </Wrapper>
  );
}
