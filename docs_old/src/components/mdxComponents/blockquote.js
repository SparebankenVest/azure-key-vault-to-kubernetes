import styled from "react-emotion";

const Blockquote = styled('blockquote')`
  padding-left: 30px;
  color: rgba(0, 0, 0, 0.42);
  font-size: 22px;
  font-weight: 400;
  letter-spacing: -0.014em;
  line-height: 1.48;
  background: #fff;
  border: none;
`;

// const Blockquote = styled('blockquote')`
//   box-sizing: border-box;
//   color: rgba(0, 0, 0, 0.8);
//   font-family: medium-content-sans-serif-font, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;
//   font-weight: 400;
//   margin-bottom: 0px;
//   margin-left: 0px;
//   margin-right: 0px;
//   margin-top: 0px;
//   overflow-wrap: break-word;
//   padding-left: 30px;
//   text-rendering: optimizelegibility;
//   word-break: break-word;
// `

// export default ({children}) => {
//   return (
//     <blockquote>
//       {children}
//     </blockquote>
//   );
// }

export default Blockquote;
