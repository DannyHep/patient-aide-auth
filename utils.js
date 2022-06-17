exports.validateEmail = function (email) {
  let regex = new RegExp("[a-z0-9]+@[a-z]+.[a-z]{2,3}");
  return regex.test(email);
};

exports.containsEmptyCredentials = function (credentials) {
  return (
    Object.values(credentials).length === 0 ||
    Object.values(credentials).some((value) => {
      value !== null && value !== "" && value.trim() !== "";
    })
  );
};
