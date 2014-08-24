/**
 * User
 *
 * @module      :: Model
 * @description :: This is the base user model
 * @docs        :: http://waterlock.ninja/documentation
 */

module.exports = {

  attributes: require('waterlock').models.user.attributes({
    
    /* e.g.
    nickname: 'string'
    */
      provider: {
          type: 'string'
      },

      uid: {
          type: 'integer'
      },

      name: {
          type: 'string',
          required: true
      },

      firstname: {
          type: 'string'
      },

      lastname: {
          type: 'string'
      },

      username: {
          type: 'string'
      },

      title: {
          type: 'string',
          defaultsTo: 'Need a Title?'
      },

       email: {
           type: 'string',
           email: true,
           required: true,
           unique: true
       },

      online: {
          type: 'boolean',
          defaultsTo: false
      },

      admin: {
          type: 'boolean',
          defaultsTo: false
      }
  }),
  
  beforeCreate: require('waterlock').models.user.beforeCreate,
  beforeUpdate: require('waterlock').models.user.beforeUpdate
};
