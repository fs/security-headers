import Category from '../models/category';
import Domain from '../models/domain';

function fetchModel(category_id) {
  return () => { return Discourse.ajax('/headlines/categories/' + category_id); };
}

function wrapDomains(domains) {
  return _.map(domains, (domain) => {
    return Domain.create({
      id: domain.id,
      name: domain.name,
      country: domain.country,
      scanResults: domain.scan_results,
      score: domain.score
    });
  })
}

function wrapModel(model) {
  return Category.create({
    id: model.id,
    title: model.title,
    parent: model.parent,
    domains: wrapDomains(model.domains),
    categories: model.categories,
    parents: model.parents
  });
}

export default Discourse.Route.extend({
  model(params) {
    return PreloadStore.getAndRemove('category', fetchModel(params.id)).then(wrapModel);
  }
})
