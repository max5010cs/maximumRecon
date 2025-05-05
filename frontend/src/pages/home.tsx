import { Link } from 'react-router-dom';

const Home = () => {
  return (
    <div>
      <h1>Welcome to MaxRecon</h1>
      <p>Your ultimate reconnaissance tool for scanning websites!</p>
      <Link to="/tool">
        <button>Start Scanning</button>
      </Link>
    </div>
  );
}

export default Home;