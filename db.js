const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const dbUrl = process.env.DB_URL || 'mongodb://localhost/api-exercise'

exports.connect = async() => {
  return await mongoose.connect(dbUrl, {useNewUrlParser: true});
}