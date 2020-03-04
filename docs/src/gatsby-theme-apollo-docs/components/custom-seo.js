import PropTypes from 'prop-types';
import React from 'react';
import {SEO} from 'gatsby-theme-apollo-core';
import socialCard from '../../assets/akv2k8s.png'

export default function CustomSEO({image, baseUrl, twitterHandle, ...props}) {
  return (
    <SEO {...props} twitterCard="summary_large_image">
      <meta property="og:image" content={socialCard} />
      {baseUrl && <meta name="twitter:image" content={baseUrl + socialCard} />}
      {twitterHandle && (
        <meta name="twitter:site" content={`@${twitterHandle}`} />
      )}
    </SEO>
  );
}

CustomSEO.propTypes = {
  baseUrl: PropTypes.string,
  image: PropTypes.string.isRequired,
  twitterHandle: PropTypes.string
};