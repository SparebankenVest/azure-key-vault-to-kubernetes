import React, { useState, useEffect } from 'react';
import {StaticQuery, graphql} from "gatsby";
import Link from "./link";
import './styles.css';
 
const Feedback = ({location}) => {
  const [feedbackReceived, setFeedbackReceived] = useState(false);

  const handleClick = (value) => {
    setFeedbackReceived(true);
    window.gtag('event', 'click', {
      'event_category': 'Helpful',
      'event_label': window.location.pathname,
      'value': value
    });
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      setFeedbackReceived(false);
    }, 5000);
    return () => clearTimeout(timer);
  });
  
  let thankYou = "";
  if(feedbackReceived) {
    thankYou = (
      <p className="feedback-response">
        Thanks for your feedback!
      </p>  
    );
  }

  return (
    <div className="feedback">
      {/* <h3>Feedback</h3> */}
      <h3 className="feedback-prompt"><span className="feedback-line" /><span className="feedback-text">Was this page helpful?</span><span className="feedback-line" /></h3>
      <button className="button feedback-yes" disabled={feedbackReceived} onClick={() => handleClick(1)}>Yes</button>
      <button className="button feedback-no" disabled={feedbackReceived} onClick={() => handleClick(0)}>No</button>
      {thankYou}
    </div>
  );
}

export default Feedback;