const layout = require("../layout");

module.exports = ({ products }) => {
  const renderedProducts = products
    .map((product) => {
      return `
      <tr>
        <td>${product.title}</td>
        <td>${product.price}</td>
        <td>
          <a href="/admin/products/${product.id}/edit">
            <button class="button is-link">
              Edit
            </button>
          </a>
        </td>
        <td>
          <form method="POST" action="/admin/products/${product.id}/delete">
            <button class="button is-danger">Delete</button>
          </form>
        </td>
      </tr>
    `;
    })
    .join("");

  return layout({
    content: `
      <a href="/admin/signout" style="font-weight:bold; font-size: 1.5rem; position: absolute; top: -2rem; bottom: 0; right: 0; ">Signout</a>
      <div class="control">
        <h1 class="subtitle">Products</h1>  
        <a href="/admin/products/new" class="button is-primary">New Product</a>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Price</th>
            <th>Edit</th>
            <th>Delete</th>
          </tr>
        </thead>
        <tbody>
          ${renderedProducts}
        </tbody>
      </table>
      
    `,
  });
};
