import React, { useState, useEffect } from 'react';
import {StaticQuery, graphql} from "gatsby";
import Link from "./link";
import styled from "react-emotion";
import './styles.css';

const Warning = () => (
  <svg width="32" height="32" viewBox="0 4 24 20" focusable="false" role="presentation"><g fill-rule="evenodd"><path d="M12.938 4.967c-.518-.978-1.36-.974-1.876 0L3.938 18.425c-.518.978-.045 1.771 1.057 1.771h14.01c1.102 0 1.573-.797 1.057-1.771L12.938 4.967z" fill="currentColor"></path><path d="M12 15a1 1 0 0 1-1-1V9a1 1 0 0 1 2 0v5a1 1 0 0 1-1 1m0 3a1 1 0 0 1 0-2 1 1 0 0 1 0 2" fill="inherit"></path></g></svg>
)

const SymbolContainer = styled('div')`
  color: rgb(255, 153, 31);
  display: inline-block;
  height: 100%;
`

const ContentContainer = styled('div')`
  padding-left: 20px;
`

const Alert = ({type, children}) => (
  <div class="alert alert-warning" style={{display: "inline-flex"}} role="alert">
    <SymbolContainer><Warning/></SymbolContainer>
    <ContentContainer>{children}</ContentContainer>
  </div>
)

export default Alert;