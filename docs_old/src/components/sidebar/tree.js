import React, {useState} from 'react';
import config from '../../../config';
import TreeNode from './treeNode';

const calculateTreeData = (edges, basePath) => {
  const originalData = config.sidebar.ignoreIndex ? edges.filter(({node: {fields: {slug}}}) => slug !== '/') : edges;
  const tree = originalData.reduce((accu, {node: { fields: {slug, title}}}) => {
    const parts = slug.split('/'); //replace(basePath)
    let {items: prevItems} = accu;
    for (const part of parts.slice(1, -1)) {
      let tmp = prevItems.find(({label}) => label == part);
      if (tmp) {
        if (!tmp.items) {
          tmp.items = [];
        }
      } else {
        tmp = {label: part, items: []};
        prevItems.push(tmp)
      }
      prevItems = tmp.items;
    }
    const existingItem = prevItems.find(({label}) => label === parts[parts.length - 1]);
    if (existingItem) {
      existingItem.url = slug;
      existingItem.title = title;
    } else {
      prevItems.push({
        label: parts[parts.length - 1],
        url: slug,
        items: [],
        title
      });
    }
    return accu;
  }, {items: []});
  const {sidebar: {forcedNavOrder = []}} = config;
  const tmp = [...forcedNavOrder];
  tmp.reverse();
  return tmp.reduce((accu, slug) => {
    const parts = slug.split('/'); //replace(basePath)
    let {items: prevItems} = accu;
    for (const part of parts.slice(1, -1)) {
      let tmp = prevItems.find(({label}) => label == part);
      if (tmp) {
        if (!tmp.items) {
          tmp.items = [];
        }
      } else {
        tmp = {label: part, items: []};
        prevItems.push(tmp)
      }
      prevItems = tmp.items;
    }
    
    // sort items alphabetically.
    prevItems.map((item) => {
      item.items = item.items
        .sort(function (a, b) {
          let a_index = a.node.frontmatter.index;
          let b_index = b.node.frontmatter.index;
          
          if(a_index && b_index && a_index != b_index ) {
            return a_index - b_index;
          }

          let a_slug = a.node.fields.slug;
          let b_slug = b.node.fields.slug;

          if (a_slug > b_slug) {
            return 1;
          } else if (a_slug < b_slug) {
            return -1;
          }
          return 0;
        });
    })
    const index = prevItems.findIndex(({label}) => label === parts[parts.length - 1]);
    accu.items.unshift(prevItems.splice(index, 1)[0]);
    return accu;
  }, tree);
}


const Tree = ({edges, basePath}) => {
  let trimedPath = basePath;// ? basePath.replace(/\/([^\/]*)$/, "") : "";
  const [treeData] = useState(() => {
    return calculateTreeData(edges, trimedPath);
  });
  const [collapsed, setCollapsed] = useState({});
  const toggle = (url) => {
    setCollapsed({
      ...collapsed,
      [url]: !collapsed[url],
    });
  }
  return (
    <TreeNode
      className={`${config.sidebar.frontLine ? 'showFrontLine' : 'hideFrontLine'} firstLevel`}
      setCollapsed={toggle}
      collapsed={collapsed}
      {...treeData}
    />
  );
}

export default Tree 
