from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, Category, CatalogItem

engine = create_engine('sqlite:///itemcatalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()


# Items for Soccer
category1 = Category(user_id=1, name="Soccer")

session.add(category1)
session.commit()

catalogItem1 = CatalogItem(user_id=1, name="Soccer Ball", description="A black and white ball used for soccer fun",
                     category=category1)

session.add(catalogItem1)
session.commit()

catalogItem2 = CatalogItem(user_id=1, name="Cleats", description="Shoes with spikes for extra grip!",
                     category=category1)

session.add(catalogItem2)
session.commit()

category2 = Category(user_id=1, name="Basketball")

session.add(category2)
session.commit()

category3 = Category(user_id=1, name="Frisbee")

session.add(category3)
session.commit()

print "Added Catalog Items"
