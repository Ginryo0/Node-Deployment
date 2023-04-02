const sum = (a, b) => {
  if (a && b) {
    return a + b;
  }
  throw new Error('Invalid Args');
};

try {
  console.log(sum(1));
} catch (err) {
  // Will not crash after error
  console.log('Error Occurred');
  // console.log(err);
}

// console.log(sum(1));
console.log('Still working');
