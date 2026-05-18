"""
MyFitnessPal MCP Server

A Model Context Protocol (MCP) server that provides tools for interacting
with MyFitnessPal data including food diary, exercises, measurements, goals,
water intake, and food search.

Authentication Methods (in order of priority):
1. Environment variables: MFP_USERNAME and MFP_PASSWORD
2. Stored session cookies: ~/.mfp_mcp/cookies.json
3. Browser cookies: Chrome/Firefox (fallback)
"""

import json
import logging
import os
import sys
from datetime import date, datetime, timedelta
from http.cookiejar import CookieJar, Cookie
from pathlib import Path
from typing import Optional, Dict, Any, List
from enum import Enum
from collections import OrderedDict
import time

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict, field_validator

# Configure logging to stderr (required for stdio transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("mfp_mcp")

# Initialize MCP server
mcp = FastMCP("myfitnesspal_mcp")

# Configuration paths
CONFIG_DIR = Path.home() / ".mfp_mcp"
COOKIES_FILE = CONFIG_DIR / "cookies.json"


# ============================================================================
# Authentication Helper Functions
# ============================================================================


def ensure_config_dir():
    """Ensure the config directory exists."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_cookies(cookies: Dict[str, str]):
    """
    Save session cookies to file for persistence.
    
    Args:
        cookies: Dictionary of cookie name -> value
    """
    ensure_config_dir()
    cookie_data = {
        "cookies": cookies,
        "saved_at": datetime.now().isoformat(),
    }
    with open(COOKIES_FILE, "w") as f:
        json.dump(cookie_data, f, indent=2)
    logger.info(f"Saved session cookies to {COOKIES_FILE}")


def load_cookies() -> Optional[Dict[str, str]]:
    """
    Load session cookies from file.
    
    Returns:
        Dictionary of cookies if file exists and is valid, None otherwise
    """
    if not COOKIES_FILE.exists():
        return None
    
    try:
        with open(COOKIES_FILE, "r") as f:
            cookie_data = json.load(f)
        
        # Check if cookies are less than 30 days old
        saved_at = datetime.fromisoformat(cookie_data.get("saved_at", "2000-01-01"))
        if datetime.now() - saved_at > timedelta(days=30):
            logger.info("Stored cookies are expired (>30 days old)")
            return None
        
        return cookie_data.get("cookies")
    except Exception as e:
        logger.warning(f"Failed to load cookies: {e}")
        return None


def dict_to_cookiejar(cookies_dict: Dict[str, str], domain: str = ".myfitnesspal.com") -> CookieJar:
    """
    Convert a dictionary of cookies to a CookieJar that can be used by myfitnesspal.Client.
    
    Args:
        cookies_dict: Dictionary of cookie name -> value
        domain: Domain for the cookies (default: .myfitnesspal.com)
    
    Returns:
        CookieJar: A CookieJar object populated with the cookies
    """
    jar = CookieJar()
    
    for name, value in cookies_dict.items():
        cookie = Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=True,
            domain_initial_dot=domain.startswith('.'),
            path="/",
            path_specified=True,
            secure=True,
            expires=int(time.time()) + 86400 * 30,  # 30 days from now
            discard=False,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": None},
            rfc2109=False,
        )
        jar.set_cookie(cookie)
    
    return jar


def authenticate_with_credentials(username: str, password: str) -> Dict[str, str]:
    """
    Authenticate with MyFitnessPal using username/password.
    
    Args:
        username: MyFitnessPal username or email
        password: MyFitnessPal password
    
    Returns:
        Dictionary of session cookies
        
    Raises:
        RuntimeError: If authentication fails
    """
    # Log authentication attempt without exposing the username
    logger.info("Authenticating with credentials")
    
    # MyFitnessPal login URL and endpoints
    LOGIN_URL = "https://www.myfitnesspal.com/account/login"
    
    try:
        with httpx.Client(follow_redirects=True, timeout=30.0) as client:
            # First, get the login page to obtain CSRF token
            response = client.get(LOGIN_URL)
            response.raise_for_status()
            
            # Extract CSRF token from cookies or page
            cookies = dict(response.cookies)
            
            # Attempt login
            login_data = {
                "username": username,
                "password": password,
            }
            
            # Try the standard form login
            login_response = client.post(
                LOGIN_URL,
                data=login_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": LOGIN_URL,
                },
            )
            
            # Check if login was successful by looking for session cookies
            all_cookies = dict(client.cookies)
            
            # MFP uses various session cookie names
            session_indicators = ["user", "session", "auth", "logged_in"]
            has_session = any(
                any(indicator in name.lower() for indicator in session_indicators)
                for name in all_cookies.keys()
            )
            
            if has_session or len(all_cookies) > len(cookies):
                logger.info("Successfully authenticated with credentials")
                return all_cookies
            else:
                # Try to check if we can access authenticated content
                test_response = client.get("https://www.myfitnesspal.com/food/diary")
                if test_response.status_code == 200 and "login" not in str(test_response.url).lower():
                    return dict(client.cookies)
                    
                raise RuntimeError("Login appeared to fail - no session cookies received")
                
    except httpx.HTTPError as e:
        raise RuntimeError(f"HTTP error during authentication: {e}")
    except Exception as e:
        raise RuntimeError(f"Authentication failed: {e}")


def get_mfp_client():
    """
    Get an authenticated MyFitnessPal client.
    
    Authentication is attempted in this order:
    1. Environment variables (MFP_USERNAME, MFP_PASSWORD)
    2. Stored session cookies (~/.mfp_mcp/cookies.json)
    3. Browser cookies (Chrome/Firefox)

    Returns:
        myfitnesspal.Client: Authenticated client instance

    Raises:
        RuntimeError: If all authentication methods fail
    """
    import myfitnesspal
    
    last_error = None
    
    # Method 1: Try environment variable credentials
    username = os.environ.get("MFP_USERNAME")
    password = os.environ.get("MFP_PASSWORD")
    
    if username and password:
        logger.info("Attempting authentication with environment credentials")
        
        # First check if we have valid stored cookies from a previous credential auth
        stored_cookies = load_cookies()
        if stored_cookies:
            logger.info("Found stored session cookies, testing validity...")
            try:
                cookiejar = dict_to_cookiejar(stored_cookies)
                client = myfitnesspal.Client(cookiejar=cookiejar)
                # Test the connection
                _ = client.get_date(date.today())
                logger.info("Stored cookies are valid")
                return client
            except Exception as e:
                logger.info(f"Stored cookies invalid: {e}, re-authenticating...")
        
        # Authenticate with credentials and save cookies
        try:
            cookies = authenticate_with_credentials(username, password)
            save_cookies(cookies)
            
            # Create client with the new cookies
            cookiejar = dict_to_cookiejar(cookies)
            client = myfitnesspal.Client(cookiejar=cookiejar)
            # Test the connection
            _ = client.get_date(date.today())
            logger.info("Successfully authenticated with credentials")
            return client
            
        except Exception as e:
            last_error = e
            logger.warning(f"Credential authentication failed: {e}")
            # Fall through to other methods
    
    # Method 2: Try stored session cookies (without credential auth)
    stored_cookies = load_cookies()
    if stored_cookies:
        logger.info("Attempting authentication with stored cookies")
        try:
            cookiejar = dict_to_cookiejar(stored_cookies)
            client = myfitnesspal.Client(cookiejar=cookiejar)
            # Test the connection
            _ = client.get_date(date.today())
            logger.info("Successfully authenticated with stored cookies")
            return client
        except Exception as e:
            last_error = e
            logger.warning(f"Stored cookie authentication failed: {e}")
    
    # Method 3: Try browser cookies (default behavior)
    logger.info("Attempting authentication with browser cookies")
    try:
        client = myfitnesspal.Client()
        # Test the connection
        _ = client.get_date(date.today())
        logger.info("Successfully authenticated with browser cookies")
        return client
    except Exception as e:
        last_error = e
        raise RuntimeError(
            f"All authentication methods failed. Last error: {str(last_error)}\n\n"
            "Please try one of these solutions:\n"
            "1. Set MFP_USERNAME and MFP_PASSWORD environment variables in Claude Desktop config\n"
            "2. Log into myfitnesspal.com in Chrome or Firefox\n"
            "3. Check ~/.mfp_mcp/cookies.json for stored session"
        )


# ============================================================================
# Data Formatting Helper Functions
# ============================================================================


def parse_date(date_str: Optional[str] = None) -> date:
    """
    Parse a date string or return today's date.

    Args:
        date_str: Date in YYYY-MM-DD format, or None for today

    Returns:
        date: Parsed date object
    """
    if date_str is None:
        return date.today()
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def format_nutrition_dict(nutrition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format nutrition dictionary for consistent output.

    Args:
        nutrition: Raw nutrition dictionary

    Returns:
        dict: Formatted nutrition data
    """
    formatted = {}
    for key, value in nutrition.items():
        if hasattr(value, "magnitude"):
            # Handle pint quantities
            formatted[key] = float(value.magnitude)
        else:
            formatted[key] = value
    return formatted


def format_meal_entry(entry) -> Dict[str, Any]:
    """
    Format a meal entry for output.

    Args:
        entry: MFP Entry object

    Returns:
        dict: Formatted entry data
    """
    return {
        "name": entry.name,
        "short_name": getattr(entry, "short_name", None),
        "quantity": getattr(entry, "quantity", None),
        "unit": getattr(entry, "unit", None),
        "nutrition": format_nutrition_dict(entry.totals),
    }


def format_exercise(exercise) -> Dict[str, Any]:
    """
    Format an exercise object for output.

    Args:
        exercise: MFP Exercise object

    Returns:
        dict: Formatted exercise data
    """
    entries = exercise.get_as_list()
    return {"name": exercise.name, "entries": entries}


def ordered_dict_to_dict(od: OrderedDict) -> Dict[str, Any]:
    """
    Convert OrderedDict with date keys to regular dict with string keys.

    Args:
        od: OrderedDict with date keys

    Returns:
        dict: Regular dict with string keys
    """
    return {str(k): v for k, v in od.items()}


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


def format_response(data: Any, format_type: ResponseFormat, title: str = "") -> str:
    """
    Format response data based on requested format.

    Args:
        data: Data to format
        format_type: Output format (markdown or json)
        title: Optional title for markdown format

    Returns:
        str: Formatted response string
    """
    if format_type == ResponseFormat.JSON:
        return json.dumps(data, indent=2, default=str)

    # Markdown format
    lines = []
    if title:
        lines.append(f"## {title}\n")

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"### {key}")
                for k, v in value.items():
                    lines.append(f"- **{k}**: {v}")
            elif isinstance(value, list):
                lines.append(f"### {key}")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"- {item.get('name', str(item))}")
                        for k, v in item.items():
                            if k != "name":
                                lines.append(f"  - {k}: {v}")
                    else:
                        lines.append(f"- {item}")
            else:
                lines.append(f"- **{key}**: {value}")
    else:
        lines.append(str(data))

    return "\n".join(lines)


# ============================================================================
# Pydantic Input Models
# ============================================================================


class GetDiaryInput(BaseModel):
    """Input model for getting food diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SearchFoodInput(BaseModel):
    """Input model for searching foods."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(
        ...,
        description="Search query for food items (e.g., 'chicken breast', 'apple')",
        min_length=1,
        max_length=200,
    )
    limit: int = Field(
        default=10,
        description="Maximum number of results to return",
        ge=1,
        le=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetFoodDetailsInput(BaseModel):
    """Input model for getting food item details."""

    model_config = ConfigDict(str_strip_whitespace=True)

    external_id: str = Field(
        ...,
        description="New-format food ID — use the 'external_id' field from mfp_search_food results (NOT 'mfp_id', which is the old-format ID used for diary writes)",
        min_length=1,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetMeasurementsInput(BaseModel):
    """Input model for getting measurements."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to retrieve (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 30 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetMeasurementInput(BaseModel):
    """Input model for setting a measurement."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to set (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    value: float = Field(
        ...,
        description="Measurement value (e.g., 185.5 for weight in lbs)",
        gt=0,
    )


class GetExercisesInput(BaseModel):
    """Input model for getting exercises."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetGoalsInput(BaseModel):
    """Input model for getting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetGoalsInput(BaseModel):
    """Input model for setting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    calories: Optional[int] = Field(
        default=None,
        description="Daily calorie goal (e.g., 2000)",
        ge=500,
        le=10000,
    )
    protein: Optional[int] = Field(
        default=None,
        description="Daily protein goal in grams (e.g., 150)",
        ge=0,
        le=1000,
    )
    carbohydrates: Optional[int] = Field(
        default=None,
        description="Daily carbohydrate goal in grams (e.g., 200)",
        ge=0,
        le=2000,
    )
    fat: Optional[int] = Field(
        default=None,
        description="Daily fat goal in grams (e.g., 65)",
        ge=0,
        le=500,
    )


class GetWaterInput(BaseModel):
    """Input model for getting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class GetReportInput(BaseModel):
    """Input model for getting nutrition reports."""

    model_config = ConfigDict(str_strip_whitespace=True)

    report_name: str = Field(
        default="Net Calories",
        description="Report name (e.g., 'Net Calories', 'Total Calories', 'Protein', 'Fat', 'Carbs', 'Cardio Calories Burned')",
    )
    report_category: str = Field(
        default="Nutrition",
        description="Report category: 'Nutrition' for food/macro reports, 'Fitness' for exercise/cardio reports",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 7 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class DeleteDiaryEntryInput(BaseModel):
    """Input model for deleting a diary entry."""

    model_config = ConfigDict(str_strip_whitespace=True)

    meal: str = Field(
        default="Breakfast",
        description="Meal name containing the entry to delete: 'Breakfast', 'Lunch', 'Dinner', or 'Snacks'",
    )
    entry_index: int = Field(
        default=0,
        description="0-based index of the entry within the meal (0 = first entry)",
        ge=0,
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class AddFoodToDiaryInput(BaseModel):
    """Input model for adding food to diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from mfp_search_food)",
        min_length=1,
    )
    meal: str = Field(
        default="Breakfast",
        description="Meal name (e.g., 'Breakfast', 'Lunch', 'Dinner', 'Snacks')",
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    quantity: float = Field(
        default=1.0,
        description="Quantity/servings (e.g., 1.5 for 1.5 servings)",
        gt=0,
        le=100,
    )
    unit: Optional[str] = Field(
        default=None,
        description="Unit/serving size description (e.g., '1 cup', '100g'). If not provided, uses default serving size from food item.",
    )
    weight_id: str = Field(
        ...,
        description="Serving size ID from mfp_search_food weight_ids list. Use weight_ids[0] from search results.",
    )


class QuickAddToDiaryInput(BaseModel):
    """Input model for quick-adding calories to diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    calories: float = Field(..., description="Number of calories to add", gt=0)
    meal: str = Field(
        default="Breakfast",
        description="Meal name (e.g., 'Breakfast', 'Lunch', 'Dinner', 'Snacks')",
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    protein: float = Field(default=0, description="Grams of protein", ge=0)
    carbohydrates: float = Field(default=0, description="Grams of carbohydrates", ge=0)
    fat: float = Field(default=0, description="Grams of fat", ge=0)


class CreateFoodInput(BaseModel):
    """Input model for creating a new food entry in the MFP database."""

    model_config = ConfigDict(str_strip_whitespace=True)

    brand: str = Field(..., description="Brand name of the food", min_length=1, max_length=200)
    description: str = Field(..., description="Description/name of the food", min_length=1, max_length=200)
    calories: int = Field(..., description="Calories per serving", ge=0, le=100000)
    fat: float = Field(..., description="Total fat in grams", ge=0)
    carbs: float = Field(..., description="Total carbohydrates in grams", ge=0)
    protein: float = Field(..., description="Protein in grams", ge=0)
    sodium: Optional[float] = Field(default=None, description="Sodium in mg", ge=0)
    potassium: Optional[float] = Field(default=None, description="Potassium in mg", ge=0)
    saturated_fat: Optional[float] = Field(default=None, description="Saturated fat in grams", ge=0)
    polyunsaturated_fat: Optional[float] = Field(default=None, description="Polyunsaturated fat in grams", ge=0)
    fiber: Optional[float] = Field(default=None, description="Dietary fiber in grams", ge=0)
    monounsaturated_fat: Optional[float] = Field(default=None, description="Monounsaturated fat in grams", ge=0)
    sugar: Optional[float] = Field(default=None, description="Sugar in grams", ge=0)
    trans_fat: Optional[float] = Field(default=None, description="Trans fat in grams", ge=0)
    cholesterol: Optional[float] = Field(default=None, description="Cholesterol in mg", ge=0)
    vitamin_a: Optional[float] = Field(default=None, description="Vitamin A in % daily value", ge=0)
    calcium: Optional[float] = Field(default=None, description="Calcium in % daily value", ge=0)
    vitamin_c: Optional[float] = Field(default=None, description="Vitamin C in % daily value", ge=0)
    iron: Optional[float] = Field(default=None, description="Iron in % daily value", ge=0)
    serving_size: str = Field(default="1 Serving", description="Serving size description (e.g., '1 cup', '100g')")
    servingspercontainer: float = Field(default=1.0, description="Number of servings per container", gt=0)
    sharepublic: bool = Field(default=False, description="Whether to share the food publicly in the MFP database")


class GetSavedMealsInput(BaseModel):
    """Input model for getting saved meals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetSavedMealInput(BaseModel):
    """Input model for getting a specific saved meal."""

    model_config = ConfigDict(str_strip_whitespace=True)

    meal_id: int = Field(..., description="Saved meal ID (obtained from mfp_get_saved_meals)")
    meal_title: str = Field(..., description="Saved meal title (obtained from mfp_get_saved_meals)", min_length=1)
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetRecipesInput(BaseModel):
    """Input model for getting recipes."""

    model_config = ConfigDict(str_strip_whitespace=True)

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetRecipeInput(BaseModel):
    """Input model for getting a specific recipe."""

    model_config = ConfigDict(str_strip_whitespace=True)

    recipe_id: int = Field(..., description="Recipe ID (obtained from mfp_get_recipes)")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class LogSavedMealInput(BaseModel):
    """Input model for logging a saved meal to the diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    meal_id: int = Field(..., description="Saved meal ID (obtained from mfp_get_saved_meals)")
    meal_name: str = Field(..., description="Saved meal name (obtained from mfp_get_saved_meals)", min_length=1)
    diary_meal: str = Field(
        default="Dinner",
        description="Diary meal slot to log into: 'Breakfast', 'Lunch', 'Dinner', or 'Snacks'",
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class SetWaterInput(BaseModel):
    """Input model for setting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    cups: float = Field(
        ...,
        description="Number of cups of water (e.g., 2.5 for 2.5 cups). Note: MyFitnessPal uses cups as the unit.",
        ge=0,
        le=50,
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


# ============================================================================
# MCP Tools
# ============================================================================


@mcp.tool(
    name="mfp_get_diary",
    annotations={
        "title": "Get Food Diary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_diary(params: GetDiaryInput) -> str:
    """
    Get the food diary for a specific date including all meals and their nutritional information.

    Returns meals (Breakfast, Lunch, Dinner, Snacks) with each food entry's name,
    quantity, and complete nutrition breakdown (calories, protein, carbs, fat, etc.).
    Also includes daily totals and goals.

    Args:
        params: GetDiaryInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Formatted diary data with meals, entries, nutrition, and goals
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        # Build response data
        data = {
            "date": str(target_date),
            "meals": {},
            "daily_totals": {},
            "daily_goals": {},
            "water": day.water,
            "notes": day.notes or "",
        }

        # Process meals
        for meal in day.meals:
            meal_data = {
                "entries": [format_meal_entry(entry) for entry in meal.entries],
                "totals": format_nutrition_dict(meal.totals),
            }
            data["meals"][meal.name] = meal_data

        # Get daily totals and goals
        totals = {}
        for entry in day.entries:
            for key, value in entry.totals.items():
                val = float(value.magnitude) if hasattr(value, "magnitude") else value
                totals[key] = totals.get(key, 0) + val
        data["daily_totals"] = totals
        data["daily_goals"] = day.goals

        return format_response(
            data, params.response_format, f"Food Diary for {target_date}"
        )

    except Exception as e:
        return f"Error retrieving diary: {str(e)}"


@mcp.tool(
    name="mfp_search_food",
    annotations={
        "title": "Search Food Database",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_search_food(params: SearchFoodInput) -> str:
    """
    Search the MyFitnessPal food database for food items.

    Returns a list of matching foods with their name, brand, serving size,
    calories, and MFP ID (which can be used with mfp_get_food_details).

    Args:
        params: SearchFoodInput containing:
            - query (str): Search query (e.g., 'chicken breast')
            - limit (int): Maximum results to return (default 10)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of matching food items with basic nutrition info
    """
    try:
        client = get_mfp_client()
        results = client.get_food_search_results(params.query)

        # Limit results
        results = results[: params.limit]

        data = {"query": params.query, "count": len(results), "results": []}

        for item in results:
            entry = {
                "name": item.name,
                "brand": item.brand,
                "serving": item.serving,
                "calories": item.calories,
                "mfp_id": item.mfp_id,
            }
            if item.old_weight_ids:
                entry["weight_ids"] = item.old_weight_ids
            if item.external_id:
                entry["external_id"] = item.external_id
            data["results"].append(entry)

        return format_response(
            data, params.response_format, f"Food Search Results for '{params.query}'"
        )

    except Exception as e:
        return f"Error searching foods: {str(e)}"


@mcp.tool(
    name="mfp_get_food_details",
    annotations={
        "title": "Get Food Item Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_food_details(params: GetFoodDetailsInput) -> str:
    """
    Get detailed nutritional information for a specific food item by its MFP ID.

    Returns complete nutrition breakdown including calories, macros (protein, carbs, fat),
    fiber, sugar, sodium, cholesterol, vitamins, minerals, and available serving sizes.

    Args:
        params: GetFoodDetailsInput containing:
            - external_id (str): New-format food ID from mfp_search_food results
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Complete nutritional information for the food item
    """
    try:
        client = get_mfp_client()
        item = client.get_food_item_details(params.external_id)

        data = {
            "external_id": params.external_id,
            "description": getattr(item, "description", "N/A"),
            "brand_name": getattr(item, "brand_name", None),
            "verified": getattr(item, "verified", False),
            "calories": getattr(item, "calories", None),
            "nutrition": {
                "protein": getattr(item, "protein", None),
                "carbohydrates": getattr(item, "carbohydrates", None),
                "fat": getattr(item, "fat", None),
                "fiber": getattr(item, "fiber", None),
                "sugar": getattr(item, "sugar", None),
                "sodium": getattr(item, "sodium", None),
                "cholesterol": getattr(item, "cholesterol", None),
                "saturated_fat": getattr(item, "saturated_fat", None),
                "polyunsaturated_fat": getattr(item, "polyunsaturated_fat", None),
                "monounsaturated_fat": getattr(item, "monounsaturated_fat", None),
                "trans_fat": getattr(item, "trans_fat", None),
                "potassium": getattr(item, "potassium", None),
                "vitamin_a": getattr(item, "vitamin_a", None),
                "vitamin_c": getattr(item, "vitamin_c", None),
                "calcium": getattr(item, "calcium", None),
                "iron": getattr(item, "iron", None),
            },
            "servings": [],
        }

        # Get serving sizes if available
        if hasattr(item, "servings"):
            for serving in item.servings:
                data["servings"].append(str(serving))

        return format_response(data, params.response_format, "Food Item Details")

    except Exception as e:
        return f"Error getting food details: {str(e)}"


@mcp.tool(
    name="mfp_get_measurements",
    annotations={
        "title": "Get Body Measurements",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_measurements(params: GetMeasurementsInput) -> str:
    """
    Get body measurements (weight, body fat, etc.) over a date range.

    Returns historical measurement data with dates and values. Useful for
    tracking weight loss progress and body composition changes.

    Args:
        params: GetMeasurementsInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - start_date (str, optional): Start date, defaults to 30 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Measurement history with dates and values
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=30)

        measurements = client.get_measurements(params.measurement, start, end)

        data = {
            "measurement_type": params.measurement,
            "start_date": str(start),
            "end_date": str(end),
            "count": len(measurements),
            "values": ordered_dict_to_dict(measurements),
        }

        # Calculate summary stats if we have data
        if measurements:
            values = list(measurements.values())
            data["summary"] = {
                "latest": values[-1] if values else None,
                "earliest": values[0] if values else None,
                "change": round(values[-1] - values[0], 2) if len(values) >= 2 else 0,
                "min": min(values),
                "max": max(values),
                "average": round(sum(values) / len(values), 2),
            }

        return format_response(
            data, params.response_format, f"{params.measurement} History"
        )

    except Exception as e:
        return f"Error getting measurements: {str(e)}"


@mcp.tool(
    name="mfp_set_measurement",
    annotations={
        "title": "Log Body Measurement",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_measurement(params: SetMeasurementInput) -> str:
    """
    Log a new body measurement (weight, body fat, etc.) for today.

    Records the measurement value in MyFitnessPal for tracking progress.

    Args:
        params: SetMeasurementInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - value (float): Measurement value (e.g., 185.5)

    Returns:
        str: Confirmation message with the logged value
    """
    try:
        client = get_mfp_client()
        client.set_measurements(params.measurement, params.value)

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.measurement}: {params.value}",
                "measurement": params.measurement,
                "value": params.value,
                "date": str(date.today()),
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting measurement: {str(e)}"


@mcp.tool(
    name="mfp_get_exercises",
    annotations={
        "title": "Get Exercise Log",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_exercises(params: GetExercisesInput) -> str:
    """
    Get logged exercises for a specific date.

    Returns both cardiovascular and strength training exercises with their
    details (duration, calories burned, sets, reps, weight, etc.).

    Args:
        params: GetExercisesInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of exercises with details and calories burned
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "exercises": []}

        for exercise in day.exercises:
            data["exercises"].append(format_exercise(exercise))

        # Calculate total calories burned
        total_burned = 0
        for ex in data["exercises"]:
            for entry in ex.get("entries", []):
                if "nutrition_information" in entry:
                    total_burned += entry["nutrition_information"].get(
                        "calories burned", 0
                    )

        data["total_calories_burned"] = total_burned

        return format_response(
            data, params.response_format, f"Exercise Log for {target_date}"
        )

    except Exception as e:
        return f"Error getting exercises: {str(e)}"


@mcp.tool(
    name="mfp_get_goals",
    annotations={
        "title": "Get Nutrition Goals",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_goals(params: GetGoalsInput) -> str:
    """
    Get the user's daily nutrition goals (calories, protein, carbs, fat, etc.).

    Returns the configured daily targets for all tracked nutrients.

    Args:
        params: GetGoalsInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily nutrition goals and targets
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "goals": day.goals}

        return format_response(data, params.response_format, "Daily Nutrition Goals")

    except Exception as e:
        return f"Error getting goals: {str(e)}"


@mcp.tool(
    name="mfp_set_goals",
    annotations={
        "title": "Update Nutrition Goals",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_set_goals(params: SetGoalsInput) -> str:
    """
    Update daily nutrition goals (calories, protein, carbs, fat).

    Sets new daily targets for the specified nutrients. Only updates the
    values that are provided; others remain unchanged.

    Args:
        params: SetGoalsInput containing:
            - calories (int, optional): Daily calorie goal
            - protein (int, optional): Daily protein goal in grams
            - carbohydrates (int, optional): Daily carb goal in grams
            - fat (int, optional): Daily fat goal in grams

    Returns:
        str: Confirmation message with updated goals
    """
    try:
        # Check that at least one goal is provided
        if not any(
            [params.calories, params.protein, params.carbohydrates, params.fat]
        ):
            return "Error: Please provide at least one goal to update (calories, protein, carbohydrates, or fat)"

        client = get_mfp_client()

        # Build kwargs for set_new_goal
        kwargs = {}
        if params.calories:
            kwargs["energy"] = params.calories
        if params.protein:
            kwargs["protein"] = params.protein
        if params.carbohydrates:
            kwargs["carbohydrates"] = params.carbohydrates
        if params.fat:
            kwargs["fat"] = params.fat

        client.set_new_goal(**kwargs)

        return json.dumps(
            {
                "success": True,
                "message": "Successfully updated nutrition goals",
                "updated_goals": {
                    "calories": params.calories,
                    "protein": params.protein,
                    "carbohydrates": params.carbohydrates,
                    "fat": params.fat,
                },
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting goals: {str(e)}"


@mcp.tool(
    name="mfp_get_water",
    annotations={
        "title": "Get Water Intake",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_water(params: GetWaterInput) -> str:
    """
    Get water intake for a specific date.

    Returns the number of cups/glasses of water logged for the day.

    Args:
        params: GetWaterInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Water intake amount for the specified date
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {
            "date": str(target_date),
            "water_cups": day.water,
            "water_ml": day.water * 236.588,  # Convert cups to ml
        }

        return json.dumps(data, indent=2)

    except Exception as e:
        return f"Error getting water intake: {str(e)}"


@mcp.tool(
    name="mfp_delete_diary_entry",
    annotations={
        "title": "Delete Diary Entry",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_delete_diary_entry(params: DeleteDiaryEntryInput) -> str:
    """
    Delete a food entry from your MyFitnessPal food diary by meal and index.

    Use mfp_get_diary first to see entries and their indices within each meal.
    The first entry in a meal has index 0, the second has index 1, and so on.

    Args:
        params: DeleteDiaryEntryInput containing:
            - meal (str): Meal name - 'Breakfast', 'Lunch', 'Dinner', or 'Snacks'
            - entry_index (int): 0-based index of the entry within the meal
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Confirmation message with the deleted entry's details
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        entry_id, entry_name = client.delete_diary_entry(
            meal=params.meal,
            entry_index=params.entry_index,
            date=target_date,
        )
        return json.dumps(
            {
                "success": True,
                "message": f"Successfully deleted '{entry_name}' from {params.meal}",
                "date": str(target_date),
                "meal": params.meal,
                "entry_index": params.entry_index,
                "entry_id": entry_id,
                "entry_name": entry_name,
            },
            indent=2,
        )
    except Exception as e:
        return f"Error deleting diary entry: {str(e)}"


@mcp.tool(
    name="mfp_add_food_to_diary",
    annotations={
        "title": "Add Food to Diary",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_add_food_to_diary(params: AddFoodToDiaryInput) -> str:
    """
    Add a food item to your MyFitnessPal food diary for a specific date and meal.

    This tool adds a food entry to your diary. You can search for foods using
    mfp_search_food to find the food ID (mfp_id) needed for this tool.

    Args:
        params: AddFoodToDiaryInput containing:
            - mfp_id (str): MyFitnessPal food item ID (from mfp_search_food)
            - meal (str): Meal name - 'Breakfast', 'Lunch', 'Dinner', or 'Snacks' (default: 'Breakfast')
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - quantity (float): Number of servings (default: 1.0)
            - unit (str, optional): Serving size description to match (e.g., '1 cup', '100g')

    Returns:
        str: Confirmation message with details of the added food entry
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        food_id = int(params.mfp_id)

        weight_id = params.weight_id
        if not weight_id:
            return (
                "Error: weight_id is required. Use mfp_search_food to find the food "
                "and get its weight_ids list, then pass weight_ids[0] as weight_id."
            )

        client.add_food_to_diary(
            food_id=food_id,
            meal=params.meal,
            date=target_date,
            quantity=params.quantity,
            weight_id=weight_id,
        )

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully added food to {params.meal}",
                "date": str(target_date),
                "meal": params.meal,
                "food_id": params.mfp_id,
                "food_name": params.mfp_id,
                "quantity": params.quantity,
            },
            indent=2,
        )

    except Exception as e:
        return f"Error adding food to diary: {str(e)}"


@mcp.tool(
    name="mfp_quick_add",
    annotations={
        "title": "Quick Add Calories",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_quick_add(params: QuickAddToDiaryInput) -> str:
    """
    Quick-add calories (and optional macros) to a meal without specifying a food item.

    Args:
        params: QuickAddToDiaryInput containing:
            - calories (float): Number of calories to add
            - meal (str): Meal name - 'Breakfast', 'Lunch', 'Dinner', or 'Snacks' (default: 'Breakfast')
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - protein (float): Grams of protein (default: 0)
            - carbohydrates (float): Grams of carbohydrates (default: 0)
            - fat (float): Grams of fat (default: 0)

    Returns:
        str: Confirmation message with details of the added entry
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)

        client.quick_add_to_diary(
            meal=params.meal,
            date=target_date,
            calories=params.calories,
            protein=params.protein,
            carbohydrates=params.carbohydrates,
            fat=params.fat,
        )

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully quick-added {params.calories} calories to {params.meal}",
                "date": str(target_date),
                "meal": params.meal,
                "calories": params.calories,
                "protein": params.protein,
                "carbohydrates": params.carbohydrates,
                "fat": params.fat,
            },
            indent=2,
        )

    except Exception as e:
        return f"Error quick-adding to diary: {str(e)}"


@mcp.tool(
    name="mfp_set_water",
    annotations={
        "title": "Log Water Intake",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_water(params: SetWaterInput) -> str:
    """
    Log water intake for a specific date.

    Sets the number of cups of water consumed for the day. MyFitnessPal uses
    cups as the unit (1 cup = ~237ml).

    Args:
        params: SetWaterInput containing:
            - cups (float): Number of cups of water (e.g., 2.5 for 2.5 cups)
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Confirmation message with the logged water amount
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        milliliters = round(params.cups * 236.588, 2)
        confirmed_ml = client.set_water(date=target_date, milliliters=milliliters)

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.cups} cups of water",
                "date": str(target_date),
                "cups": params.cups,
                "milliliters": confirmed_ml,
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting water intake: {str(e)}"


@mcp.tool(
    name="mfp_get_report",
    annotations={
        "title": "Get Nutrition Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_report(params: GetReportInput) -> str:
    """
    Get a nutrition report over a date range.

    Returns daily values for the specified nutrient/metric over the date range.
    Useful for analyzing trends and patterns in nutrition intake.

    Args:
        params: GetReportInput containing:
            - report_name (str): Report type (e.g., 'Net Calories', 'Protein')
            - start_date (str, optional): Start date, defaults to 7 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily values and summary statistics for the report period
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=7)

        report = client.get_report(
            report_name=params.report_name,
            report_category=params.report_category,
            lower_bound=start,
            upper_bound=end,
        )

        data = {
            "report_name": params.report_name,
            "start_date": str(start),
            "end_date": str(end),
            "values": (
                ordered_dict_to_dict(report) if isinstance(report, OrderedDict) else report
            ),
        }

        # Calculate summary stats
        if report:
            values = list(report.values())
            numeric_values = [v for v in values if isinstance(v, (int, float))]
            if numeric_values:
                data["summary"] = {
                    "total": sum(numeric_values),
                    "average": round(sum(numeric_values) / len(numeric_values), 2),
                    "min": min(numeric_values),
                    "max": max(numeric_values),
                }

        return format_response(
            data, params.response_format, f"{params.report_name} Report"
        )

    except Exception as e:
        return f"Error getting report: {str(e)}"


@mcp.tool(
    name="mfp_create_food",
    annotations={
        "title": "Create Food Entry",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_create_food(params: CreateFoodInput) -> str:
    """
    Create a new food entry in the MyFitnessPal food database.

    Submits a new food with full nutritional information. The food will appear
    in search results after a short delay. Required fields are brand, description,
    calories, fat, carbs, and protein. All other nutrition fields are optional.

    Args:
        params: CreateFoodInput containing brand, description, calories, macros,
                and optional nutrition details, serving info, and visibility.

    Returns:
        str: Confirmation message with the submitted food details
    """
    try:
        client = get_mfp_client()
        client.set_new_food(
            brand=params.brand,
            description=params.description,
            calories=params.calories,
            fat=params.fat,
            carbs=params.carbs,
            protein=params.protein,
            sodium=params.sodium,
            potassium=params.potassium,
            saturated_fat=params.saturated_fat,
            polyunsaturated_fat=params.polyunsaturated_fat,
            fiber=params.fiber,
            monounsaturated_fat=params.monounsaturated_fat,
            sugar=params.sugar,
            trans_fat=params.trans_fat,
            cholesterol=params.cholesterol,
            vitamin_a=params.vitamin_a,
            calcium=params.calcium,
            vitamin_c=params.vitamin_c,
            iron=params.iron,
            serving_size=params.serving_size,
            servingspercontainer=params.servingspercontainer,
            sharepublic=params.sharepublic,
        )

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully created food '{params.brand} {params.description}'",
                "note": "The food may take a few minutes to appear in search results.",
                "food": {
                    "brand": params.brand,
                    "description": params.description,
                    "calories": params.calories,
                    "fat": params.fat,
                    "carbs": params.carbs,
                    "protein": params.protein,
                    "serving_size": params.serving_size,
                    "public": params.sharepublic,
                },
            },
            indent=2,
        )

    except Exception as e:
        return f"Error creating food: {str(e)}"


@mcp.tool(
    name="mfp_get_saved_meals",
    annotations={
        "title": "Get Saved Meals",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_saved_meals(params: GetSavedMealsInput) -> str:
    """
    Get all saved/custom meals from MyFitnessPal, including ingredients.

    Returns a list of saved meals with their IDs, names, and ingredient summaries.
    Use mfp_get_saved_meal to get full details for a specific meal, or
    mfp_log_saved_meal to log a meal to the diary.

    Args:
        params: GetSavedMealsInput containing:
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of saved meals with their IDs, names, and ingredient lists
    """
    try:
        client = get_mfp_client()
        meals_raw = client.get_meals_detailed()

        data = {
            "count": len(meals_raw),
            "meals": [
                {
                    "id": meal["meal_id"],
                    "name": meal["description"],
                    "foods": meal.get("foods", []),
                }
                for meal in meals_raw
            ],
        }

        return format_response(data, params.response_format, "Saved Meals")

    except Exception as e:
        return f"Error getting saved meals: {str(e)}"


@mcp.tool(
    name="mfp_get_saved_meal",
    annotations={
        "title": "Get Saved Meal Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_saved_meal(params: GetSavedMealInput) -> str:
    """
    Get detailed ingredient and nutrition information for a specific saved meal.

    Returns the full list of ingredients with nutritional breakdown for the meal.
    Use mfp_get_saved_meals first to get the meal ID and title.

    Args:
        params: GetSavedMealInput containing:
            - meal_id (int): Saved meal ID (from mfp_get_saved_meals)
            - meal_title (str): Saved meal title (from mfp_get_saved_meals)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Full ingredient list and nutritional information for the saved meal
    """
    try:
        client = get_mfp_client()
        meal = client.get_meal(params.meal_id, params.meal_title)

        data = {
            "id": params.meal_id,
            "title": params.meal_title,
            "meal": meal,
        }

        return format_response(data, params.response_format, f"Saved Meal: {params.meal_title}")

    except Exception as e:
        return f"Error getting saved meal: {str(e)}"


@mcp.tool(
    name="mfp_get_recipes",
    annotations={
        "title": "Get Recipes",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_recipes(params: GetRecipesInput) -> str:
    """
    Get all saved recipes from MyFitnessPal.

    Returns a list of recipes with their IDs and names. Use mfp_get_recipe
    to get the full ingredient and nutrition details for a specific recipe.
    Note: MyFitnessPal returns up to 10 recipes.

    Args:
        params: GetRecipesInput containing:
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of recipes with their IDs and names
    """
    try:
        client = get_mfp_client()
        recipes = client.get_recipes()

        data = {
            "count": len(recipes),
            "recipes": [{"id": recipe_id, "name": name} for recipe_id, name in recipes.items()],
        }

        return format_response(data, params.response_format, "Recipes")

    except Exception as e:
        return f"Error getting recipes: {str(e)}"


@mcp.tool(
    name="mfp_get_recipe",
    annotations={
        "title": "Get Recipe Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_recipe(params: GetRecipeInput) -> str:
    """
    Get detailed ingredient and nutrition information for a specific recipe.

    Returns the full list of ingredients with nutritional breakdown for the recipe.
    Use mfp_get_recipes first to get the recipe ID.

    Args:
        params: GetRecipeInput containing:
            - recipe_id (int): Recipe ID (from mfp_get_recipes)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Full ingredient list and nutritional information for the recipe
    """
    try:
        client = get_mfp_client()
        recipe = client.get_recipe(params.recipe_id)

        data = {
            "id": params.recipe_id,
            "recipe": recipe,
        }

        return format_response(data, params.response_format, "Recipe Details")

    except Exception as e:
        return f"Error getting recipe: {str(e)}"




@mcp.tool(
    name="mfp_log_saved_meal",
    annotations={
        "title": "Log Saved Meal to Diary",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_log_saved_meal(params: LogSavedMealInput) -> str:
    """
    Log a saved meal to the MyFitnessPal food diary.

    Uses the add_favorites endpoint to log the meal by name. Use
    mfp_get_saved_meals to find the meal_name first.

    Args:
        params: LogSavedMealInput containing:
            - meal_id (int): Saved meal ID (from mfp_get_saved_meals, currently unused)
            - meal_name (str): Saved meal name (from mfp_get_saved_meals)
            - diary_meal (str): Diary slot — 'Breakfast', 'Lunch', 'Dinner', or 'Snacks'
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Confirmation of the logged meal entry
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)

        result = client.log_saved_meal(params.meal_name, params.diary_meal, target_date)
        return json.dumps({"success": True, "entry": result}, indent=2)

    except Exception as e:
        return f"Error logging saved meal: {str(e)}"


# ============================================================================
# Cookie Management Tool
# ============================================================================


@mcp.tool()
def refresh_browser_cookies(browser: str = "chrome") -> str:
    """
    Extract and save session cookies from your web browser.
    
    Use this tool when authentication fails and you need to refresh your
    MyFitnessPal session. You must be logged into myfitnesspal.com in your
    browser for this to work.
    
    Args:
        browser: Which browser to extract cookies from ("chrome" or "firefox")
    
    Returns:
        Success message or error description
    """
    import browser_cookie3
    
    try:
        # Get browser cookie function
        if browser.lower() == "chrome":
            cj = browser_cookie3.chrome(domain_name='.myfitnesspal.com')
        elif browser.lower() == "firefox":
            cj = browser_cookie3.firefox(domain_name='.myfitnesspal.com')
        else:
            return f"Unsupported browser: {browser}. Use 'chrome' or 'firefox'."
        
        # Extract cookies to dictionary
        cookies = {c.name: c.value for c in cj}
        
        # Check for session token
        if '__Secure-next-auth.session-token' not in cookies:
            return (
                f"No session token found in {browser}. "
                "Please make sure you are logged into myfitnesspal.com in your browser, "
                "then try again."
            )
        
        # Save cookies
        save_cookies(cookies)
        
        # Verify they work
        try:
            import myfitnesspal
            cookiejar = dict_to_cookiejar(cookies)
            client = myfitnesspal.Client(cookiejar=cookiejar)
            _ = client.get_date(date.today())
            
            return (
                f"Successfully extracted and verified {len(cookies)} cookies from {browser}. "
                "Authentication is now working!"
            )
        except Exception as e:
            return (
                f"Cookies were extracted from {browser} but verification failed: {e}. "
                "The session may have expired - try logging into myfitnesspal.com again."
            )
            
    except Exception as e:
        error_msg = str(e)
        if "Operation not permitted" in error_msg:
            return (
                f"Permission denied reading {browser} cookies. "
                "This can happen due to macOS security restrictions. "
                "Try running this command in Terminal instead:\n\n"
                f"{COOKIES_FILE.parent}/../venv/bin/python -c \""
                "import browser_cookie3, json, os; "
                "from datetime import datetime; "
                f"cj = browser_cookie3.{browser}(domain_name='.myfitnesspal.com'); "
                "cookies = {c.name: c.value for c in cj}; "
                "os.makedirs(os.path.expanduser('~/.mfp_mcp'), exist_ok=True); "
                "open(os.path.expanduser('~/.mfp_mcp/cookies.json'), 'w').write("
                "json.dumps({'cookies': cookies, 'saved_at': datetime.now().isoformat()}, indent=2)); "
                "print('Cookies refreshed!')\""
            )
        return f"Error extracting cookies from {browser}: {e}"


# ============================================================================
# Main Entry Point
# ============================================================================


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()