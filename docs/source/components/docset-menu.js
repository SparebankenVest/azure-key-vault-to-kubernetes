import React, { useContext } from 'react';
import styled from '@emotion/styled';
import {
  NavItemsContext,
  NavItemTitle,
  NavItemDescription
} from 'gatsby-theme-apollo-docs';
import { colors } from 'gatsby-theme-apollo-core';

const Wrapper = styled.div({
  display: 'grid',
  gridTemplateColumns: `repeat(auto-fill, minmax(270px, 1fr))`,
  gridGap: 12,
  paddingTop: 8
});

const MenuItem = styled.div({
  display: 'flex'
});

const TextWrapper = styled.div({
  color: colors.text1
});

const StyledLink = styled.a({
  color: 'inherit',
  textDecoration: 'none',
  ':hover': {
    textDecoration: 'underline'
  }
});

export default function DocsetMenu() {
  const navItems = useContext(NavItemsContext);
  return (
    <Wrapper>
      {navItems.filter((navItem) => {
        return !(navItem.omitLandingPage);
      }).map((navItem, index) => (
        <MenuItem key={navItem.url}>
          <TextWrapper>
            <NavItemTitle>
              <StyledLink href={navItem.url}>
                {navItem.title}
              </StyledLink>
            </NavItemTitle>
            <NavItemDescription>{navItem.description}</NavItemDescription>
          </TextWrapper>
        </MenuItem>
      ))}
    </Wrapper>
  );
}
