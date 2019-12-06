import React from 'react';
import {StaticQuery, graphql} from "gatsby";
import Link from "./link";
import './styles.css';

const Feedback = ({location}) => {
  const handleClick = (value) => {
    window.gtag('event', 'click', {
      'event_category': 'Helpful',
      'event_label': window.location.pathname,
      'value': value
    });
  };

  const thankYou = (
    <p className="feedback-response">
      Thanks for your feedback!
    </p>
  );

  return (
    <div className="feedback">
      {/* <h3>Feedback</h3> */}
      <h3 className="feedback-prompt"><span className="feedback-line" /><span className="feedback-text">Was this page helpful?</span><span className="feedback-line" /></h3>
      <button className="button feedback-yes" onClick={() => handleClick(1)}>Yes</button>
      <button className="button feedback-no" onClick={() => handleClick(0)}>No</button>
    </div>
  );
}

export default Feedback;